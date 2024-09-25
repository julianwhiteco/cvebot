package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-redis/redis/v8"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/google/uuid"
)

var (
	apiKey        string                 // NVD API key
	telegramToken string                 // Telegram bot token
	cachedNVDData map[string]interface{} // In-memory cache for NVD data
	dataMutex     sync.RWMutex           // Mutex for thread-safe access to cachedNVDData

	redisClient *redis.Client          // Redis client
	ctx         = context.Background() // Context for Redis operations
	bot         *tgbotapi.BotAPI       // Telegram bot instance
)

func main() {
	// Define command-line flags.
	flag.StringVar(&apiKey, "nvd-api-key", "", "NVD API Key")
	flag.StringVar(&telegramToken, "telegram-token", "", "Telegram Bot Token")
	flag.Parse()

	// Read from environment variables if not set via flags at runtime.
	if apiKey == "" {
		apiKey = os.Getenv("NVD_API_KEY")
	}
	if telegramToken == "" {
		telegramToken = os.Getenv("TELEGRAM_TOKEN")
	}

	// And now we validate that both apiKey and telegramToken are set on start.
	if apiKey == "" || telegramToken == "" {
		log.Fatal("NVD API key and Telegram bot token must be provided via command-line flags or environment variables")
	}

	// Initialise Redis client.
	redisClient = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// Start goroutine for NIST NVD API & run Telegram bot.
	go startDataFetching()
	startTelegramBot()
}

func startDataFetching() {
	fetchNVDData()
	processNVDData()
	ticker := time.NewTicker(1 * time.Hour) // Schedule re-download & message-queue once an hr.
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fetchNVDData()
			processNVDData()
		}
	}
}

// -----
// Functions to download and process NIST NVD data.
// -----

func fetchNVDData() {
	println("Fetching NVD Data.")
	// Temporal calculations for the last 4 hours in UTC-5.
	loc := time.FixedZone("UTC-5", -5*3600)
	now := time.Now().In(loc)
	HoursAgo := now.Add(-1 * time.Hour)

	pubStartDate := HoursAgo.Format("2006-01-02T15:04:05.000-07:00")
	pubEndDate := now.Format("2006-01-02T15:04:05.000-07:00")

	// NIST API address
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=%s&pubEndDate=%s", pubStartDate, pubEndDate)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Println("Error creating request:", err)
		return
	}

	req.Header.Set("apiKey", apiKey)
	resp, err := client.Do(req)

	if err != nil {
		log.Println("Error making request:", err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Request failed with status code: %d\n", resp.StatusCode)
		return
	}

	bodyText, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Println("Error reading response body:", err)
		return
	}

	// And now parse the JSON response from NIST.
	var result map[string]interface{}
	err = json.Unmarshal(bodyText, &result)
	if err != nil {
		log.Println("Error parsing JSON:", err)
		return
	}

	// Store the parsed JSON data in memory.
	dataMutex.Lock()
	cachedNVDData = result
	dataMutex.Unlock()

	// Extract the totalResults data so we know how many were read.
	totalResults, ok := result["totalResults"].(float64)
	if !ok {
		log.Println("Could not parse totalResults from response")
		return
	}

	// Todo: Print to syslog instead of terminal.
	fmt.Printf("Successfully pulled data down. Total vulnerabilities in the last hour: %d\n", int(totalResults))
}

func processNVDData() {
	println("Processing NVD Data, one moment...")
	dataMutex.RLock()
	data := cachedNVDData
	dataMutex.RUnlock()

	if data == nil {
		log.Println("No NVD data to process")
		return
	}

	vulnerabilities, ok := data["vulnerabilities"].([]interface{})
	if !ok {
		log.Println("Could not parse vulnerabilities from NVD data")
		return
	}

	// Fetch all user tracking entries from Redis store.
	keys, err := redisClient.Keys(ctx, "track:*").Result()
	if err != nil {
		log.Println("Error fetching keys from Redis:", err)
		return
	}

	log.Printf("Processing %d user tracking entries", len(keys))

	for _, key := range keys {
		userData, err := redisClient.HGetAll(ctx, key).Result()
		if err != nil {
			log.Println("Error fetching user data from Redis:", err)
			continue
		}

		trackType := userData["type"]
		trackValue := userData["track_value"]
		telegramID := userData["telegram_id"]

		if trackType == "Asset" {
			// Search by phrase the user has entered, which could be a vendor, product, or tag.
			searchVulnerabilitiesByAsset(vulnerabilities, trackValue, telegramID)
		} else if trackType == "Source" {
			// Search by sourceIdentifier which is the email address associated.
			searchVulnerabilitiesBySource(vulnerabilities, trackValue, telegramID)
		}
	}
}

// -----
// Functions to search user queries against in-memory store.
// -----

func searchVulnerabilitiesByAsset(vulnerabilities []interface{}, asset, telegramID string) {
	println("Searching vulns...")
	for _, v := range vulnerabilities {
		vuln, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		cve := vuln["cve"].(map[string]interface{})
		cveID := cve["id"].(string)
		print("checking CVE ID ", cveID)
		descriptions := cve["descriptions"].([]interface{})
		for _, d := range descriptions {
			println(descriptions)
			desc := d.(map[string]interface{})
			value := desc["value"].(string)
			log.Printf("Checking CVE '%s' for asset '%s'", cveID, asset)
			if containsIgnoreCase(value, asset) {
				log.Printf("Match found for asset '%s' in CVE '%s'", asset, cveID)
				sendNotification(cve, telegramID)
				break
			}
		}
	}
}

func searchVulnerabilitiesBySource(vulnerabilities []interface{}, sourceEmail, telegramID string) {
	for _, v := range vulnerabilities {
		vuln, ok := v.(map[string]interface{})

		if !ok {
			continue
		}

		cve := vuln["cve"].(map[string]interface{})
		sourceIdentifier := cve["sourceIdentifier"].(string)

		if equalsIgnoreCase(sourceIdentifier, sourceEmail) {
			sendNotification(cve, telegramID)
		}
	}
}

// -----
// Telegram Bot Setup/Comms
// -----

func startTelegramBot() {
	var err error
	bot, err = tgbotapi.NewBotAPI(telegramToken)
	if err != nil {
		log.Panic(err)
	}

	bot.Debug = false
	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		// If we got a message, handle it.
		if update.Message != nil {
			handleMessage(update.Message)
		}
	}
}

func sendNotification(cve map[string]interface{}, telegramID string) {
	cveID := cve["id"].(string)
	descriptions := cve["descriptions"].([]interface{})
	description := descriptions[0].(map[string]interface{})["value"].(string)
	firstSentence := getFirstSentence(description)
	url := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
	message := fmt.Sprintf("A new vulnerability CVE has been released that matches one of your tracks: %s\n\n%s\n\n Read More: %s", cveID, firstSentence, url)

	log.Printf("Sending notification to Telegram ID %s for CVE %s", telegramID, cveID)

	// Convert telegramID to int64 type.
	chatID, err := strconv.ParseInt(telegramID, 10, 64)
	if err != nil {
		log.Println("Error converting telegramID to int64:", err)
		return
	}

	// Send message.
	msg := tgbotapi.NewMessage(chatID, message)
	_, err = bot.Send(msg)
	if err != nil {
		log.Println("Error sending message to user:", err)
	}
}

// -----
// Data/content validation
// -----

func containsIgnoreCase(str, substr string) bool {
	str = strings.ToLower(str)
	substr = strings.ToLower(substr)
	return strings.Contains(str, substr)
}

func equalsIgnoreCase(str1, str2 string) bool {
	return strings.EqualFold(str1, str2)
}

func getFirstSentence(text string) string {
	for i, r := range text {
		if r == '.' || r == '!' || r == '?' {
			if isPartOfNumber(text, i) {
				continue
			}
			return text[:i+1]
		}
	}
	// If no sentence terminator (.) was found, return all text.
	return text
}

func isPartOfNumber(text string, index int) bool {
	// Check the character before the period...
	if index > 0 && unicode.IsDigit(rune(text[index-1])) {
		// Check the character after the period...
		if index+1 < len(text) && unicode.IsDigit(rune(text[index+1])) {
			return true
		}
	}
	return false
}

// -----
// User conversational logic.
// -----

func handleCommand(message *tgbotapi.Message) {
	switch message.Command() {
	case "start":
		sendMainMenu(message.Chat.ID)
	default:
		msg := tgbotapi.NewMessage(message.Chat.ID, "Unknown command. Please use /start to begin.")
		bot.Send(msg)
	}
}

func sendMainMenu(chatID int64) {
	buttons := tgbotapi.NewReplyKeyboard(
		// Row 1
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("Look up CVE ID"),
			tgbotapi.NewKeyboardButton("Track Product/Vendor"),
		),
		// Row 2
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("Track Source"),
			tgbotapi.NewKeyboardButton("Remove a Track"),
		),
	)

	msg := tgbotapi.NewMessage(chatID, "What would you like to do?")
	msg.ReplyMarkup = buttons
	bot.Send(msg)
}

func handleMessage(message *tgbotapi.Message) {
	log.Printf("[%s] %s", message.From.UserName, message.Text)
	if message.IsCommand() {
		handleCommand(message)
	} else {
		switch message.Text {

		case "Look up CVE ID":
			msg := tgbotapi.NewMessage(message.Chat.ID, "Please enter the CVE ID (CVE-2024-00000):")
			backButton := tgbotapi.NewKeyboardButton("Back")
			keyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(backButton),
			)
			msg.ReplyMarkup = keyboard
			bot.Send(msg)
			userKey := fmt.Sprintf("user:%d", message.From.ID)
			redisClient.HSet(ctx, userKey, "state", "awaiting_cve_id")

		case "Track Product/Vendor":
			msg := tgbotapi.NewMessage(message.Chat.ID, "Please enter the the phrase, vendor name, product name, or asset to track (ie 'WordPress', 'Microsoft', 'Python'):")
			backButton := tgbotapi.NewKeyboardButton("Back")
			keyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(backButton),
			)
			msg.ReplyMarkup = keyboard
			bot.Send(msg)
			userKey := fmt.Sprintf("user:%d", message.From.ID)
			redisClient.HSet(ctx, userKey, "state", "awaiting_asset")

		case "Track Source":
			msg := tgbotapi.NewMessage(message.Chat.ID, "Please enter the source (ie 'name@address.com') to track:")
			backButton := tgbotapi.NewKeyboardButton("Back")
			keyboard := tgbotapi.NewReplyKeyboard(
				tgbotapi.NewKeyboardButtonRow(backButton),
			)
			msg.ReplyMarkup = keyboard
			bot.Send(msg)
			userKey := fmt.Sprintf("user:%d", message.From.ID)
			redisClient.HSet(ctx, userKey, "state", "awaiting_email")

		case "Remove a Track":
			handleRemoveTrackedItem(message)
		default:
			handleUserInput(message)
		}
	}
}

func handleUserInput(message *tgbotapi.Message) {
	chatID := message.Chat.ID
	userID := message.From.ID
	userKey := fmt.Sprintf("user:%d", userID)

	// Get user state from Redis.
	state, err := redisClient.HGet(ctx, userKey, "state").Result()
	if err == redis.Nil {
		// No state has been found, send main menu.
		sendMainMenu(chatID)
		return
	} else if err != nil {
		log.Println("Error getting user state from Redis:", err)
		return
	}

	// "Global "Back" button handler.
	if message.Text == "Back" {
		redisClient.HDel(ctx, userKey, "state")
		sendMainMenu(chatID)
		return
	}

	switch state {
	case "awaiting_asset":
		asset := message.Text
		storeTrackingData(userID, message.From.UserName, "Asset", asset)
		msg := tgbotapi.NewMessage(chatID, "Product, Vendor, or Keyword tracked successfully.")
		bot.Send(msg)
		// Reset user state.
		redisClient.HDel(ctx, userKey, "state")
		// Send main menu again.
		sendMainMenu(chatID)

	case "awaiting_email":
		email := message.Text
		storeTrackingData(userID, message.From.UserName, "Source", email)
		msg := tgbotapi.NewMessage(chatID, "Source (email address) tracked successfully.")
		bot.Send(msg)
		// Reset user state.
		redisClient.HDel(ctx, userKey, "state")
		// Send main menu again.
		sendMainMenu(chatID)

	case "awaiting_cve_id":
		cveID := message.Text
		description := lookupCVE(cveID)
		msg := tgbotapi.NewMessage(chatID, description)
		bot.Send(msg)
		// Reset user state.
		redisClient.HDel(ctx, userKey, "state")
		// Send main menu again.
		sendMainMenu(chatID)

	case "awaiting_removal":
		itemToRemove := message.Text
		err := removeTrackedItem(userID, itemToRemove)
		if err != nil {
			msg := tgbotapi.NewMessage(chatID, "Error removing the tracked item.")
			bot.Send(msg)
			log.Println("Error removing tracked item:", err)
		} else {
			msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("Removed: %s", itemToRemove))
			bot.Send(msg)
			// After confirming removal, send the main menu.
			sendMainMenu(chatID)
		}
		// Reset user state.
		redisClient.HDel(ctx, userKey, "state")

	default:
		sendMainMenu(chatID)
	}
}

// -----
// Logic for CVE lookups
// -----

func lookupCVE(cveID string) string {
	// Validate and standardise the CVE ID format.
	normalizedCVEID, err := validateCVEID(cveID)
	if err != nil {
		return err.Error()
	}

	// Craft API call to NVD.
	cveDetails, err := fetchCVEDetails(normalizedCVEID)
	if err != nil {
		return err.Error()
	}

	return formatCVEResponse(cveDetails)
}

func validateCVEID(input string) (string, error) {
	cveID := strings.TrimSpace(input)

	// Prepend "CVE-" if missing from query.
	if !strings.HasPrefix(strings.ToUpper(cveID), "CVE-") {
		cveID = "CVE-" + cveID
	}

	// Regex for validating CVE input.
	re := regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
	if !re.MatchString(strings.ToUpper(cveID)) {
		return "", fmt.Errorf("Invalid CVE ID format. Please provide a valid CVE ID (e.g., CVE-2022-12345).")
	}

	return strings.ToUpper(cveID), nil
}

func fetchCVEDetails(cveID string) (map[string]interface{}, error) {
	// Construct the URL with the CVE ID.
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("Error creating request: %v", err)
	}

	// Setting API key in the request header.
	req.Header.Set("apiKey", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error making request to NVD API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API request failed with status code: %d", resp.StatusCode)
	}

	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response body: %v", err)
	}

	// NIST response is in JSON and must be parsed.
	var result map[string]interface{}
	err = json.Unmarshal(bodyText, &result)
	if err != nil {
		return nil, fmt.Errorf("Error parsing JSON: %v", err)
	}

	return result, nil
}

func formatCVEResponse(data map[string]interface{}) string {
	vulnerabilities, ok := data["vulnerabilities"].([]interface{})
	if !ok || len(vulnerabilities) == 0 {
		return "CVE not found."
	}

	vuln, ok := vulnerabilities[0].(map[string]interface{})
	if !ok {
		return "Error parsing CVE data."
	}

	cve := vuln["cve"].(map[string]interface{})
	cveID := cve["id"].(string)

	descriptions, ok := cve["descriptions"].([]interface{})
	description := "No description available."
	if ok && len(descriptions) > 0 {
		// Find the English description...
		for _, d := range descriptions {
			desc := d.(map[string]interface{})
			if lang, exists := desc["lang"]; exists && lang == "en" {
				if value, exists := desc["value"].(string); exists {
					description = value
					break
				}
			}
		}
	}

	url := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
	message := fmt.Sprintf("%s\n\n%s\n\nRead More: %s", cveID, description, url)
	return message
}

func removeTrackedItem(userID int64, displayText string) error {
	// Fetch user's tracked items.
	trackedItems, err := getUserTrackedItems(userID)
	if err != nil {
		return err
	}

	// Find the item with the matching display text.
	var keyToRemove string
	for _, item := range trackedItems {
		if item.DisplayText == displayText {
			keyToRemove = item.Key
			break
		}
	}

	if keyToRemove == "" {
		return fmt.Errorf("tracked item was not found")
	}

	// Delete the key from Redis.
	err = redisClient.Del(ctx, keyToRemove).Err()
	if err != nil {
		return err
	}

	return nil
}

func handleRemoveTrackedItem(message *tgbotapi.Message) {
	chatID := message.Chat.ID
	userID := message.From.ID

	// Fetch user's tracked items from Redis
	trackedItems, err := getUserTrackedItems(userID)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "Error fetching your tracked items.")
		bot.Send(msg)
		log.Println("Error fetching tracked items:", err)
		return
	}

	if len(trackedItems) == 0 {
		msg := tgbotapi.NewMessage(chatID, "You have no tracks saved.")
		bot.Send(msg)
		return
	}

	// Create buttons for each tracked item.
	var buttonRows [][]tgbotapi.KeyboardButton
	for _, item := range trackedItems {
		button := tgbotapi.NewKeyboardButton(item.DisplayText)
		buttonRows = append(buttonRows, tgbotapi.NewKeyboardButtonRow(button))
	}

	// Add the "Back" button.
	backButton := tgbotapi.NewKeyboardButton("Back")
	buttonRows = append(buttonRows, tgbotapi.NewKeyboardButtonRow(backButton))

	// Set user state to awaiting_removal.
	userKey := fmt.Sprintf("user:%d", userID)
	redisClient.HSet(ctx, userKey, "state", "awaiting_removal")

	// Send message with buttons.
	msg := tgbotapi.NewMessage(chatID, "Select a name or source to remove:")
	msg.ReplyMarkup = tgbotapi.NewReplyKeyboard(buttonRows...)

	bot.Send(msg)
}

type TrackedItem struct {
	Key         string
	DisplayText string // ie "Asset: Microsoft" or "Email: example@example.com"
}

func getUserTrackedItems(userID int64) ([]TrackedItem, error) {
	var trackedItems []TrackedItem

	// Fetch all tracking keys.
	keys, err := redisClient.Keys(ctx, "track:*").Result()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		data, err := redisClient.HGetAll(ctx, key).Result()
		if err != nil {
			log.Println("Error fetching data for key", key, ":", err)
			continue
		}

		telegramID := data["telegram_id"]
		storedUserID, err := strconv.ParseInt(telegramID, 10, 64)
		if err != nil {
			log.Println("Error parsing telegram_id:", err)
			continue
		}

		if storedUserID == userID {
			trackType := data["type"]
			trackValue := data["track_value"]
			displayText := fmt.Sprintf("%s: %s", trackType, trackValue)
			trackedItems = append(trackedItems, TrackedItem{
				Key:         key,
				DisplayText: displayText,
			})
		}
	}

	return trackedItems, nil
}

func storeTrackingData(userID int64, username, trackType, trackValue string) {
	uniqueID := uuid.New().String()
	timestamp := time.Now().Unix()

	trackingKey := fmt.Sprintf("track:%s", uniqueID)
	redisClient.HSet(ctx, trackingKey, map[string]interface{}{
		"telegram_username": username,
		"telegram_id":       strconv.FormatInt(userID, 10),
		"type":              trackType,
		"track_value":       trackValue,
		"date_added":        timestamp,
	})
}
