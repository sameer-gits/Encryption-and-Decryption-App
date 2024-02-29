package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
)

func createHash(key string) []byte {
    hasher := sha256.New()
    hasher.Write([]byte(key))
    return hasher.Sum(nil)
}

func encrypt(data []byte, passphrase string) []byte {
    block, _ := aes.NewCipher([]byte(createHash(passphrase)))
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, gcm.NonceSize())
    io.ReadFull(rand.Reader, nonce)
    ciphertext := gcm.Seal(nonce, nonce, data, nil)
    return ciphertext
}


func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM((block))
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, _ := gcm.Open (nil, nonce, ciphertext, nil)
	return plaintext
}


func decryptFile(w http.ResponseWriter, r *http.Request) {
    // Parse the form file
    r.ParseMultipartForm(10 << 20) // Limit size to 10MB
    file, _, err := r.FormFile("fileDecrypt")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer file.Close()

    // Read the file content
    fileBytes, err := io.ReadAll(file)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    filenameDecrypt := r.Form.Get("filenameDecrypt")
    passphraseDecrypt := r.Form.Get("passphraseDecrypt")
   

    // Encrypt the file content
    decryptedData := decrypt(fileBytes, passphraseDecrypt)

    // Save the encrypted data to a file for download
    err = os.WriteFile(filenameDecrypt, decryptedData, 0644)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Generate download link
    downloadLink := "<a href=\"/download?filename="+filenameDecrypt+"\">Download Decrypted File</a>"

    // Write the link to the response
    w.Header().Set("Content-Type", "text/html")
    fmt.Fprintf(w, "%s", downloadLink)
}


func encryptFile(w http.ResponseWriter, r *http.Request) {
    // Parse the form file
    r.ParseMultipartForm(10 << 20) // Limit size to 10MB
    file, _, err := r.FormFile("file")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    defer file.Close()

    // Read the file content
    fileBytes, err := io.ReadAll(file)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    filename := r.Form.Get("filename")
    passphrase := r.Form.Get("passphrase")

    // Encrypt the file content
    encryptedData := encrypt(fileBytes, passphrase)

    // Save the encrypted data to a file for download
    err = os.WriteFile(filename+".enc", encryptedData, 0644)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Generate download link
    downloadLink := "<a href=\"/download?filename=" + filename + ".enc\">Download Encrypted File</a>"

    // Write the link to the response
    w.Header().Set("Content-Type", "text/html")
    fmt.Fprintf(w, "%s", downloadLink)
}
	

func downloadFile(w http.ResponseWriter, r *http.Request) {
    // Extract the filename from the query parameters
    filename := r.URL.Query().Get("filename")

    // Set the appropriate headers for file download
    w.Header().Set("Content-Disposition", "attachment; filename="+filename)
    w.Header().Set("Content-Type", "application/octet-stream")

    // Serve the file
    http.ServeFile(w, r, filename)
}



func main() {
	http.HandleFunc("/decrypt", decryptFile)
    http.HandleFunc("/encrypt", encryptFile)
	http.HandleFunc("/download", downloadFile)
	http.Handle("/", http.FileServer(http.Dir(".")))
    http.ListenAndServe(":8080", nil)
}
