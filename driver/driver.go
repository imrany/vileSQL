package driver

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
)

type WriteOpResponse struct{
	RowsAffected int64 `json:"rows_affected"`
	LastInsertId int64 `json:"last_insert_id"`
	Message string `json:"message"`
}

type ReadOpResponse struct {
	Columns  []string                 `json:"columns"`
	Types    []string                 `json:"types"`
	Rows     []map[string]interface{} `json:"rows"`
	RowCount int                      `json:"row_count"`
	Limited  bool                     `json:"limited"`
}

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

// Run executes an SQL write queries (Write, Update, Delete, Alter, e.g INSERT, DELETE)
func (d *Driver) Exec(sql string) (WriteOpResponse, error) {
    if sql == "" {
        return WriteOpResponse{}, fmt.Errorf("[-] Error: SQL query is empty")
    }
    if d.connectLink == "" {
        return WriteOpResponse{}, fmt.Errorf("[-] Error: No active connection")
    }

    executeAPIEndpoint := fmt.Sprintf("%s/query", d.connectLink)
    reqBody, _ := json.Marshal(map[string]string{"sql": sql})

    req, err := http.NewRequest("POST", executeAPIEndpoint, bytes.NewBuffer(reqBody))
    if err != nil {
        return WriteOpResponse{}, fmt.Errorf("[-] Failed to create request: %v", err)
    }
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return WriteOpResponse{}, fmt.Errorf("[-] HTTP request failed: %v", err)
    }
    defer resp.Body.Close()

    // Read response body
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return WriteOpResponse{}, fmt.Errorf("[-] Error reading response body: %v", err)
    }

    // Check for successful API response
    if resp.StatusCode != http.StatusOK {
        return WriteOpResponse{}, fmt.Errorf("[-] API error: received HTTP %d - %s", resp.StatusCode, string(body))
    }

	var bodyParse WriteOpResponse
	err = json.Unmarshal(body, &bodyParse)
	if err != nil {
		return WriteOpResponse{}, fmt.Errorf("[-] Failed to Parse response: %v", err)
	}
    return bodyParse, nil
}

// Run an SQL Read queries (Read-only, e.g SELECT)
func (d *Driver) Query(sql string) (ReadOpResponse, error) {
    if sql == "" {
        return ReadOpResponse{}, fmt.Errorf("[-] Error: SQL query is empty")
    }
    if d.connectLink == "" {
        return ReadOpResponse{}, fmt.Errorf("[-] Error: No active connection")
    }

    executeAPIEndpoint := fmt.Sprintf("%s/query", d.connectLink)
    reqBody, _ := json.Marshal(map[string]string{"sql": sql})

    req, err := http.NewRequest("POST", executeAPIEndpoint, bytes.NewBuffer(reqBody))
    if err != nil {
        return ReadOpResponse{}, fmt.Errorf("[-] Failed to create request: %v", err)
    }
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return ReadOpResponse{}, fmt.Errorf("[-] HTTP request failed: %v", err)
    }
    defer resp.Body.Close()

    // Read response body
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return ReadOpResponse{}, fmt.Errorf("[-] Error reading response body: %v", err)
    }

    // Check for successful API response
    if resp.StatusCode != http.StatusOK {
        return ReadOpResponse{}, fmt.Errorf("[-] API error: received HTTP %d - %s", resp.StatusCode, string(body))
    }

    var bodyParse ReadOpResponse
	
	err = json.Unmarshal(body, &bodyParse)
	if err != nil {
		return ReadOpResponse{}, fmt.Errorf("[-] Failed to parse response: %v", err)
	}
	return bodyParse, nil
}
