package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
)

var (
	verbose bool
	debug   bool
)

type Result struct {
	URL     string
	Context string
}

func detectNormalization(urlStr string, client *http.Client) (bool, string) {
	testCases := []struct {
		original   string
		normalized string
	}{
		{"Special\u212A", "SpecialK"},       // Kelvin sign
		{"UNIＯN", "UNION"},                  // Fullwidth Latin Capital Letter O
		{"ＡDMIN", "ADMIN"},                  // Fullwidth Latin Capital Letter A
		{"１=1", "1=1"},                      // Fullwidth Digit One
		{"ＯR 1=1", "OR 1=1"},                // Fullwidth Latin Capital Letter O
		{"ＳELECT", "SELECT"},                // Fullwidth Latin Capital Letters
		{"ＦROM", "FROM"},                    // Fullwidth Latin Capital Letters
		{"ＷHERE", "WHERE"},                  // Fullwidth Latin Capital Letters
		{"<ſcript>", "<script>"},            // Latin Small Letter Long S
		{"javascript\uFF1a", "javascript:"}, // Fullwidth Colon
		{"ＡND", "AND"},                      // Fullwidth Latin Capital Letters
		{"ＸSS", "XSS"},                      // Fullwidth Latin Capital Letters
		{"＜img src=x onerror=alert(1)＞", "<img src=x onerror=alert(1)>"}, // Fullwidth Less-Than and Greater-Than Sign
		{"سلام", "سلام"},   // Arabic Hello (testing non-Latin scripts)
		{"مرحبا", "مرحبا"}, // Arabic Welcome (testing non-Latin scripts)
		{"ﬁ", "fi"},        // NFKC normalization specific
		{"ﬂ", "fl"},        // NFKC normalization specific
		{"㎡", "m²"},        // NFKC normalization specific
		{"Ⅷ", "VIII"},      // NFKC normalization specific
	}

	for _, tc := range testCases {
		testURL := fmt.Sprintf("%s?q=%s", urlStr, url.QueryEscape(tc.original))

		if verbose {
			fmt.Printf("\nScanning: %s\n", testURL)
		}

		resp, err := client.Get(testURL)
		if err != nil {
			if debug {
				fmt.Printf("\nError scanning %s: %v\n", urlStr, err)
			}
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			if debug {
				fmt.Printf("\nError reading response from %s: %v\n", urlStr, err)
			}
			continue
		}

		bodyStr := string(body)
		if debug {
			fmt.Printf("Response body: %s\n", bodyStr)
		}

		bodyLower := strings.ToLower(bodyStr)
		originalLower := strings.ToLower(tc.original)
		normalizedLower := strings.ToLower(tc.normalized)

		if strings.Contains(bodyLower, normalizedLower) && !strings.Contains(bodyLower, originalLower) {
			return true, fmt.Sprintf("Normalized '%s' to '%s'", tc.original, tc.normalized)
		}

		if strings.Contains(bodyStr, tc.normalized) ||
			(!strings.Contains(bodyStr, tc.original) && strings.Contains(bodyStr, url.QueryEscape(tc.normalized))) {
			return true, fmt.Sprintf("Normalized '%s' to '%s'", tc.original, tc.normalized)
		}
	}

	return false, ""
}

func main() {
	fmt.Println("🕵️ UniSnoop - Unicode Normalization Vulnerability Detector")

	var urlFlag string
	var urlListFlag string
	var proxyFlag string
	var pocFlag bool
	var proofFlag bool
	var outputFile string
	var concurrency int

	flag.StringVar(&urlFlag, "url", "", "Single URL to scan")
	flag.StringVar(&urlListFlag, "list", "", "File containing list of URLs to scan")
	flag.StringVar(&proxyFlag, "proxy", "", "Proxy URL (e.g. http://127.0.0.1:8080)")
	flag.BoolVar(&pocFlag, "poc", false, "Show proof of concept for detection")
	flag.BoolVar(&proofFlag, "proof", false, "Show curl command for verification")
	flag.StringVar(&outputFile, "o", "", "Output file to write results")
	flag.IntVar(&concurrency, "c", 10, "Number of concurrent workers")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&debug, "debug", false, "Debug output")
	flag.Parse()

	var urls []string

	if urlFlag != "" {
		urls = append(urls, urlFlag)
	} else if urlListFlag != "" {
		file, err := os.Open(urlListFlag)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				urls = append(urls, scanner.Text())
			}
		} else {
			fmt.Println("Please provide either a single URL (-url), a list of URLs (-list), or pipe URLs via stdin")
			os.Exit(1)
		}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	if proxyFlag != "" {
		proxyURL, err := url.Parse(proxyFlag)
		if err != nil {
			fmt.Printf("Invalid proxy URL: %v\n", err)
			os.Exit(1)
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}

	bar := progressbar.NewOptions(len(urls),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(15),
		progressbar.OptionSetDescription("[cyan][1/2][reset] Scanning URLs..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))

	var detectedURLs []Result
	for _, u := range urls {
		detected, context := detectNormalization(u, client)
		if detected {
			fmt.Printf("\n🎉 Unicode Normalization detected: %s\n", u)
			fmt.Printf("Context: %s\n", context)
			if pocFlag {
				fmt.Println("Proof of Concept:")
				fmt.Printf("1. Original URL: %s\n", u)
				fmt.Printf("2. Malicious URL: %s?q=UNIＯN%%20SELECT%%201,2,3%%20FROM%%20users\n", u)
				fmt.Println("3. Explanation: The server normalizes the fullwidth characters to their ASCII equivalents.")
				fmt.Println("   This can be used to bypass input filters and potentially lead to SQL injection.")
				fmt.Println("4. Impact: An attacker could potentially execute arbitrary SQL queries, leading to unauthorized data access or manipulation.")
				fmt.Println("5. Remediation: Implement proper input validation and sanitization before normalization.")
				fmt.Println("   Consider using parameterized queries to prevent SQL injection.")
			}
			if proofFlag {
				fmt.Printf("Verification: curl -v '%s?q=Special%%E2%%84%%AA'\n", u)
			}
			detectedURLs = append(detectedURLs, Result{URL: u, Context: context})
		} else if verbose {
			fmt.Printf("\n❌ Unicode Normalization not detected: %s\n", u)
		}
		bar.Add(1)
	}

	summary := fmt.Sprintf("\n📊 Summary:\n")
	summary += fmt.Sprintf("Total URLs scanned: %d\n", len(urls))
	summary += fmt.Sprintf("URLs with Unicode Normalization detected: %d\n", len(detectedURLs))

	if len(detectedURLs) > 0 {
		summary += "\nDetected URLs and contexts:\n"
		for _, r := range detectedURLs {
			summary += fmt.Sprintf("- %s (Context: %s)\n", r.URL, r.Context)
		}
	}

	fmt.Println(summary)

	if outputFile != "" {
		err := ioutil.WriteFile(outputFile, []byte(summary), 0644)
		if err != nil {
			fmt.Printf("Error writing to output file: %v\n", err)
		} else {
			fmt.Printf("Results written to %s\n", outputFile)
		}
	}
}
