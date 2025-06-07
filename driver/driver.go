package driver

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
)

type Credentials struct {
    Host  string
    Token string
}

type Driver struct {
    Credentials Credentials
    connectLink string
}

// Connect establishes the API link
func (d *Driver) Connect() error {
    if d.Credentials.Host == "" {
        return fmt.Errorf("[-] Connection error: Host is empty")
    }
    if d.Credentials.Token == "" {
        return fmt.Errorf("[-] Connection error: Token is empty")
    }
    
    d.connectLink = fmt.Sprintf("%s/api/shared/%s", d.Credentials.Host, d.Credentials.Token)
    return nil
}

// Run executes an SQL query via API
func (d *Driver) Run(sql string) (interface{}, error) {
    if sql == "" {
        return nil, fmt.Errorf("[-] Error: SQL query is empty")
    }
    if d.connectLink == "" {
        return nil, fmt.Errorf("[-] Error: No active connection")
    }

    executeAPIEndpoint := fmt.Sprintf("%s/query", d.connectLink)
    reqBody, _ := json.Marshal(map[string]string{"sql": sql})

    req, err := http.NewRequest("POST", executeAPIEndpoint, bytes.NewBuffer(reqBody))
    if err != nil {
        return nil, fmt.Errorf("[-] Failed to create request: %v", err)
    }
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, fmt.Errorf("[-] HTTP request failed: %v", err)
    }
    defer resp.Body.Close()

    // Read response body
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("[-] Error reading response body: %v", err)
    }

    // Check for successful API response
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("[-] API error: received HTTP %d - %s", resp.StatusCode, string(body))
    }

    return string(body), nil
}
