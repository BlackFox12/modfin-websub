package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

// Subscriber represents a subscriber
type Subscriber struct {
	CallbackURL string `json:"callbackURL"`
	Lease       string `json:"lease"` // Not used right now
	Secret      string `json:"secret"`
}

// SubscribersMap maps topic to list of subscribers
var SubscribersMap map[string][]Subscriber

func main() {
	SubscribersMap = make(map[string][]Subscriber)
	http.HandleFunc("/", HandleRoot)
	http.HandleFunc("/publish", HandlePublish)

	log.Fatal(http.ListenAndServe("hub:8080", nil))
}

// HandleRoot handles the root endpoint
func HandleRoot(w http.ResponseWriter, r *http.Request) {
	form, err := parseSubscription(r)
	if err != nil {
		sendStatus(w, http.StatusBadRequest, "Could not parse form.")
	}
	mode := form.Get("hub.mode")

	log.Printf("Got a request")
	if mode == "subscribe" {
		sendStatus(w, http.StatusAccepted, "Status Accepted, will try to subscribe")
		HandleSubscribe(r)
	} else if mode == "unsubscribe" {
		sendStatus(w, http.StatusAccepted, "Status Accepted, will try to unsubscribe")
		handleUnSubscribe(r)
	} else {
		// Send error response for unrecognized mode
		sendStatus(w, http.StatusBadRequest, "Unrecognized mode, should be either subscribe or unsubscribe, was: "+mode)

		// Make GET request to callback URL with denied mode
		callback := form.Get("hub.callback")
		topic := form.Get("hub.topic")
		makeDenyGet(callback, topic, "Unrecognized mode")
	}
}

// HandleSubscribe handles subscription requests
func HandleSubscribe(r *http.Request) {
	log.Printf("Got a subscribe request")
	form, _ := parseSubscription(r)
	callback := form.Get("hub.callback")
	topic := form.Get("hub.topic")
	lease := form.Get("hub.lease_seconds")
	secret := form.Get("hub.secret")

	newSub := Subscriber{
		CallbackURL: callback,
		Lease:       lease,
		Secret:      secret,
	}

	challenge := makeChallenge()
	intentOk := verifyIntent(callback, "subscribe", topic, challenge, lease)
	if intentOk {
		addOrUpdateSubscriber(newSub, topic)
		log.Printf("Handled subscription without issues")
		return
	}
	log.Printf("There was an issue verifying intent, will not add subscriber")
}

// handleUnSubscribe handles unsubscription requests
func handleUnSubscribe(r *http.Request) {
	log.Printf("Got an unsubscribe request")
	form, _ := parseSubscription(r)
	callback := form.Get("hub.callback")
	topic := form.Get("hub.topic")
	lease := form.Get("hub.lease_seconds")

	challenge := makeChallenge()
	intentOk := verifyIntent(callback, "unsubscribe", topic, challenge, lease)
	if !intentOk {
		log.Printf("Failed verifying intent")
		return
	}

	// Find the index of the subscription in the map
	index, topicExists := findSubscription(topic, callback)
	if !topicExists || index < 0 {
		makeDenyGet(callback, topic, "Cannot unsubscribe, subscription does not exist")
		return
	}

	// Remove the subscription from the map
	subscriptions := SubscribersMap[topic]
	SubscribersMap[topic] = append(subscriptions[:index], subscriptions[index+1:]...)

	log.Printf("Handled unsubscription")
}

// HandlePublish handles publishing data to subscribers
func HandlePublish(w http.ResponseWriter, request *http.Request) {
	log.Println("Publishing data to subscribers")

	// Simulated JSON data
	resp := make(map[string]string)
	resp["message"] = "This is a test message from the WebSub Hub"
	jsonData, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}

	// Iterate over all subscriptions and send JSON data to each subscriber
	for _, subscribers := range SubscribersMap {
		for _, subscriber := range subscribers {
			callbackURL := subscriber.CallbackURL
			secret := subscriber.Secret
			/*
				When looping over all the subscribers, I could have a time-stamp for when they were added,
				and if {time_now - time_added > lease_second}, then remove the subscriber and don't send any data.
			*/

			// Marshal JSON data
			payload := []byte(jsonData)

			// Compute HMAC signature
			signature, err := computeHMAC(secret, payload)
			if err != nil {
				log.Printf("Error computing HMAC signature: %v", err)
				continue
			}

			// Post JSON data to subscriber's callback URL with HMAC signature in header
			req, err := http.NewRequest("POST", callbackURL, bytes.NewBuffer(payload))
			if err != nil {
				log.Printf("Error creating request: %v", err)
				continue
			}

			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Hub-Signature", "sha256="+signature)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Error posting data to subscriber %s: %v", callbackURL, err)
				continue
			}
			defer resp.Body.Close()

			// Check the response status code
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				log.Printf("Data posted successfully to subscriber %s", callbackURL)
			} else {
				log.Printf("Error posting data to subscriber %s: Status %d", callbackURL, resp.StatusCode)
			}
		}
	}
	fmt.Fprintf(w, "Data published to subscribers")
}

func parseSubscription(r *http.Request) (url.Values, error) {
	err := r.ParseForm()
	if err != nil {
		log.Printf("Could not parse form. Err: %s", err)
		return nil, err
	}
	return r.Form, nil
}

// verifyIntent verifies the intent of the subscription or unsubscription request
func verifyIntent(callback, mode, topic, challenge, lease string) bool {
	response := makeAcceptGet(callback, mode, topic, challenge, lease)

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			// Handle error reading response body
			makeDenyGet(callback, topic, "Failed to read response body, it should match hub challenge")
			return false
		}
		// Compare response body with challenge
		if bytes.Equal(body, []byte(challenge)) {
			return true
		} else {
			makeDenyGet(callback, topic, "Body does not match challenge")
			return false
		}
	} else {
		denyReason := fmt.Sprintf("Not a valid status code after verification, should be 2XX, was: %d",
			response.StatusCode)
		makeDenyGet(callback, topic, denyReason)
		return false
	}
}

// addOrUpdateSubscriber adds or updates a subscriber in the SubscribersMap
func addOrUpdateSubscriber(sub Subscriber, topic string) {
	// Check if there's an existing subscription for the same topic and callback URL
	index, topicExists := findSubscription(topic, sub.CallbackURL)
	subscriptions := []Subscriber{}
	if topicExists {
		subscriptions = SubscribersMap[topic]
	}
	if index >= 0 {
		// Update existing subscription
		subscriptions[index] = sub
	} else {
		// Append new subscription to the list
		subscriptions = append(subscriptions, sub)
	}
	SubscribersMap[topic] = subscriptions
}

// sendStatus Sends a http status response with a message in the body
func sendStatus(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	resp := make(map[string]string)
	resp["message"] = message
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(jsonResp)
	return
}

// makeDenyGet makes a GET request with denied mode to the subscriber's callback URL
func makeDenyGet(callbackURL, topic, reason string) {
	// Construct GET request to callback URL with denied mode and reason
	reqURL := fmt.Sprintf("%s?hub.mode=denied&hub.topic=%s&hub.reason=%s", callbackURL, topic, reason)
	_, err := http.Get(reqURL)
	if err != nil {
		log.Printf("Error making deny request to callback URL: %v", err)
	}
}

// makeAcceptGet makes a GET request to the subscriber's callback URL with acceptance mode
func makeAcceptGet(callbackURL, mode, topic, challenge, lease string) *http.Response {
	// Construct GET request to callback URL with acceptance mode and topic
	reqURL := fmt.Sprintf("%s?hub.mode=%s&hub.topic=%s&hub.challenge=%s&hub.lease_seconds=%s",
		callbackURL,
		mode,
		topic,
		challenge,
		lease)
	response, err := http.Get(reqURL)
	if err != nil {
		log.Printf("Error making accept request to callback URL: %v", err)
	}
	return response
}

// findSubscription finds the index of a subscription in the SubscribersMap
func findSubscription(topic string, callback string) (int, bool) {
	subscriptions, ok := SubscribersMap[topic]
	if !ok {
		return -1, false
	}

	// Look for an existing subscription with the same callback URL
	var index = -1
	for i, subscriber := range subscriptions {
		if subscriber.CallbackURL == callback {
			index = i
			break
		}
	}
	return index, true
}

// makeChallenge generates a random challenge string
func makeChallenge() string {
	// Generate 16 random bytes
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Printf("Error generating random string: %v", err)
		return ""
	}

	// Encode random bytes to hexadecimal string
	randomString := hex.EncodeToString(randomBytes)
	return randomString
}

// computeHMAC computes the HMAC signature using SHA-256 algorithm
func computeHMAC(secret string, data []byte) (string, error) {
	h := hmac.New(sha256.New, []byte(secret))
	_, err := h.Write(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
