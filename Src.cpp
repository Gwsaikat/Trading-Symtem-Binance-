#include <iostream>
#include <string>
#include <curl/curl.h>
#include <chrono>
#include <openssl/hmac.h>
#include <iomanip>
#include <sstream>
#include "Include/json.hpp"

using json = nlohmann::json;

// Function to handle cURL response
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Function to send a cURL request
std::string sendRequest(const std::string& url, const std::string& apiKey = "", const std::string& apiSecret = "", const std::string& payload = "", bool isPost = false) {
    std::string response;
    CURL* curl = curl_easy_init();

    if (!curl) {
        std::cerr << "CURL initialization failed!" << std::endl;
        return "";
    }

    std::cout << "\n🚀 Sending request to: " << url << std::endl;

    // Set up cURL options
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, "C:/Trading System Project/certs/cacert.pem");

    // Set headers
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    if (!apiKey.empty()) {
        headers = curl_slist_append(headers, ("X-MBX-APIKEY: " + apiKey).c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Add payload if provided
    if (!payload.empty() && isPost) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    }

    // Set the request method
    if (isPost) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
    }

    // Perform the request
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "CURL request failed: " << curl_easy_strerror(res) << std::endl;
    } else {
        std::cout << "\nBinance Response:\n" << response << std::endl;
    }

    // Clean up
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return response;
}

// Function to create HMAC SHA256 signature
std::string createSignature(const std::string& data, const std::string& secret) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len;

    HMAC(EVP_sha256(), secret.c_str(), secret.length(),
         reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), result, &result_len);

    std::ostringstream ss;
    for (unsigned int i = 0; i < result_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
    }
    return ss.str();
}

// Function to place an order
void placeOrder(const std::string& apiKey, const std::string& apiSecret, const std::string& symbol, const std::string& side, const std::string& price, const std::string& quantity, const std::string& type) {
    // Get Binance server time
    std::string url = "https://testnet.binancefuture.com/fapi/v1/time";
    std::string response = sendRequest(url);

    if (!response.empty()) {
        json jsonData = json::parse(response);
        long long serverTime = jsonData["serverTime"];

        // Build the query string
        std::stringstream queryStream;
        queryStream << "symbol=" << symbol
                    << "&side=" << side
                    << "&type=" << type
                    << "&quantity=" << quantity
                    << "&recvWindow=5000"
                    << "&timestamp=" << serverTime;

        if (type == "LIMIT") {
            queryStream << "&price=" << price << "&timeInForce=GTC";
        }

        // Generate the signature
        std::string queryString = queryStream.str();
        std::string signature = createSignature(queryString, apiSecret);
        queryString += "&signature=" + signature;

        // Send the request
        std::string orderUrl = "https://testnet.binancefuture.com/fapi/v1/order";
        std::string orderResponse = sendRequest(orderUrl, apiKey, apiSecret, queryString, true); // Use POST method

        if (!orderResponse.empty()) {
            std::cout << "Place Order Response: " << orderResponse << std::endl;
        } else {
            std::cerr << "Error placing order." << std::endl;
        }
    } else {
        std::cerr << "Error getting Binance server time." << std::endl;
    }
}

// Function to cancel an order
void cancelOrder(const std::string& apiKey, const std::string& apiSecret, const std::string& symbol, const std::string& orderId) {
    long long timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    std::string queryString = "symbol=" + symbol + "&orderId=" + orderId + "&recvWindow=5000&timestamp=" + std::to_string(timestamp);
    std::string signature = createSignature(queryString, apiSecret);
    queryString += "&signature=" + signature;

    std::string url = "https://testnet.binancefuture.com/fapi/v1/order?" + queryString;
    std::string response = sendRequest(url, apiKey, apiSecret);

    std::cout << "Cancel Order Response: " << response << std::endl;
}

// Function to check Binance server time
void checkBinanceTime() {
    std::string url = "https://testnet.binancefuture.com/fapi/v1/time";
    std::string response = sendRequest(url);

    if (!response.empty()) {
        std::cout << "Binance Server Time Response: " << response << std::endl;
    } else {
        std::cerr << "Error getting Binance server time." << std::endl;
    }
}

int main() {
    std::string apiKey = "51216e32081dff3a777634f73f07e25e4a3c24ed60c26fb9fce583bd3cbf50d9";
    std::string apiSecret = "21ed6acbb7f24c1164132e34c2693cb2abb5c949495d4300c7bf11bff9655c61";

    int choice;
    while (true) {
        std::cout << "\nBinance Futures API Client\n";
        std::cout << "1. Place an order (Market/LIMIT)\n";
        std::cout << "2. Cancel an order\n";
        std::cout << "3. Check Binance Server Time\n";
        std::cout << "4. Exit\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        if (choice == 4) break;

        std::string symbol = "BTCUSDT";
        std::string side = "BUY";
        std::string price = "40000";
        std::string quantity = "0.002";
        std::string orderId;
        std::string type;

        switch (choice) {
            case 1:
                std::cout << "Enter Order Type (MARKET / LIMIT): ";
                std::cin >> type;
                placeOrder(apiKey, apiSecret, symbol, side, price, quantity, type);
                break;

            case 2:
                std::cout << "Enter Order ID to Cancel: ";
                std::cin >> orderId;
                cancelOrder(apiKey, apiSecret, symbol, orderId);
                break;

            case 3:
                checkBinanceTime();
                break;

            default:
                std::cerr << "Invalid choice. Please try again." << std::endl;
                break;
        }
    }
    return 0;
}