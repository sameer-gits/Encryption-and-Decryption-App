package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	_ "github.com/lib/pq"
)

const (
	keySize       = 32 // AES-256 requires a 32-byte key
	nonceSize     = 12 // 96 bits for AES-GCM
	fileChunkSize = 8192
)

func generateKey(passphrase string) ([]byte, error) {
	hasher := sha256.New()
	if _, err := hasher.Write([]byte(passphrase)); err != nil {
		return nil, fmt.Errorf("failed to write to hasher: %v", err)
	}
	key := hasher.Sum(nil)
	return key[:keySize], nil
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %v", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key, err := generateKey(passphrase)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %v", err)
	}

	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext is too short")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}
	return plaintext, nil
}

// func getDatabaseURL() string {
// 	// Construct and return the database URL
// 	return fmt.Sprintf("postgresql://%s:%s@%s:%s/%s",
// 		os.Getenv("DB_USER"),
// 		os.Getenv("DB_PASSWORD"),
// 		os.Getenv("DB_HOST"),
// 		os.Getenv("DB_PORT"),
// 		os.Getenv("DB_NAME"))
// }

func encryptFile(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20) // Limit size to 10MB
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	plaintext, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
    userFilename := r.FormValue("filename")
	passphrase := r.FormValue("passphrase")
	encryptedData, err := encrypt(plaintext, passphrase)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	filename := userFilename + ".enc"

	db, err := sql.Open("postgres", "postgresql://postgres:fd3aAddCg--b2FCDC6*D6gA-Fdd63-*a@viaduct.proxy.rlwy.net:19978/railway")

	if err != nil {
        log.Fatal(err)
    }

	defer db.Close()

// 	insertstmt, err := db.Prepare("INSERT INTO encrypted_files (filename, data) VALUES ($1, $2) RETURNING id")

// if err != nil {
//     log.Fatal(err)
// }

// defer insertstmt.Close()

// // Execute the INSERT statement
// var fileid interface{} // Define a variable to store the returned ID
// err = insertstmt.QueryRow(filename, encryptedData).Scan(&fileid) // Scan the returned ID into fileid

// if err != nil {
//     log.Fatal(err)
// }

// downloadstmt, err := db.Prepare("SELECT id FROM encrypted_files WHERE id = $1")

// if err != nil {
//     log.Fatal(err)
// }

// defer downloadstmt.Close()

// var fileidStr string
// switch fileid := fileid.(type) {
// case int:
//     fileidStr = strconv.Itoa(fileid)
// case string:
//     fileidStr = fileid
// default:
//     log.Fatal("Unexpected type for fileid")
// }

// downloadLink := "<a href=\"/download?filename=" + fileidStr + "\">Download Encrypted File</a>"
// w.Header().Set("Content-Type", "text/html")
// fmt.Fprintf(w, "%s", downloadLink)

insertstmt, err := db.Prepare("INSERT INTO encrypted_files (filename, data) VALUES ($1, $2) RETURNING id")

if err != nil {
    log.Fatal(err)
}

defer insertstmt.Close()

// Execute the INSERT statement
var fileid int // Define a variable to store the returned ID
err = insertstmt.QueryRow(filename, encryptedData).Scan(&fileid) // Scan the returned ID into fileid

if err != nil {
    log.Fatal(err)
}

if err := os.WriteFile(filename, encryptedData, 0644); err != nil {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

downloadLink := "<a href=\"/download?filename=" + filename + "\">Download Encrypted File</a>"
w.Header().Set("Content-Type", "text/html")
fmt.Fprintf(w, "%s", downloadLink)

}

func decryptFile(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20) // Limit size to 10MB
	file, _, err := r.FormFile("fileDecrypt")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	ciphertext, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	passphrase := r.FormValue("passphraseDecrypt")
	plaintext, err := decrypt(ciphertext, passphrase)
	if err != nil {
		// If decryption fails, remove the existing decrypted file if it exists
		filename := r.FormValue("filenameDecrypt")
		if _, statErr := os.Stat(filename); statErr == nil {
			removeErr := os.Remove(filename)
			if removeErr != nil {
				http.Error(w, removeErr.Error(), http.StatusInternalServerError)
				return
			}
		}

		// Return the noLink HTML
		noLink := "<div id=\"download-link-decrypt\"></div>"
		w.Header().Set("Content-Type", "text/html") // Set the content type before writing response
		fmt.Fprintf(w, "%s", noLink)                // Write the HTML response
		return                                       // Exit the function after writing the response
	}

	// Decryption successful, write the decrypted file and provide download link
	filename := r.FormValue("filenameDecrypt")
	if err := os.WriteFile(filename, plaintext, 0644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	downloadLink := "<a href=\"/download?filename=" + filename + "\">Download Decrypted File</a>"
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "%s", downloadLink)
}

func downloadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Filename not provided", http.StatusBadRequest)
		return
	}

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, filename)
}



func main() {
	http.HandleFunc("/encrypt", encryptFile)
	http.HandleFunc("/decrypt", decryptFile)
	http.HandleFunc("/download", downloadFile)
	http.Handle("/", http.FileServer(http.Dir(".")))

	http.ListenAndServe(":8080", nil)
}


