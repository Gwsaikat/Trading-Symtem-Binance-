#include <iostream>
#include <curl/curl.h>

int main() {
    CURL* curl;
    CURLcode res;

    // Initialize libcurl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize a CURL handle
    curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL." << std::endl;
        return 1;
    }

    // Set the URL to fetch
    curl_easy_setopt(curl, CURLOPT_URL, "https://test.deribit.com/api/v2/public/ping");

    // Disable SSL verification
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // Perform the request
    res = curl_easy_perform(curl);

    // Check for errors
    if (res != CURLE_OK) {
        std::cerr << "Curl Error: " << curl_easy_strerror(res) << std::endl;
    }

    // Cleanup
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}