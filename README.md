# Tugas-End-to-End-Secure-Message-Delivery_II3230

Repository ini berisi implementasi sistem pengiriman pesan aman secara end-to-end untuk Latihan Praktikum II3230 Keamanan Informasi K02/K03.

## Struktur Repository

- `keygen.py` : generate RSA-2048 key pair untuk Alice dan Bob (jalankan sekali sebelum memulai).
- `alice.py` : implementasi sisi pengirim — menjalankan seluruh 7 langkah pengamanan pesan lalu mengirimnya via TCP socket.
- `bob.py` : implementasi sisi penerima — menerima payload, mendekripsi, dan memverifikasi pesan dari Alice.
- `alice_private.pem` : private key Alice, digunakan untuk membuat digital signature (**rahasia, jangan disebarkan**).
- `alice_public.pem` : public key Alice, digunakan Bob untuk verifikasi signature (boleh disebarkan).
- `bob_private.pem` : private key Bob, digunakan untuk mendekripsi AES key (**rahasia, jangan disebarkan**).
- `bob_public.pem` : public key Bob, digunakan Alice untuk mengenkripsi AES key (boleh disebarkan).

> File `.pem` dibuat otomatis setelah menjalankan `key_generator.py`.

## Cara Menjalankan

### 1. Install dependency

```bash
pip install cryptography
```

### 2. Generate key pair (hanya sekali)

```bash
python key_generator.py
```

Perintah ini akan membuat 4 file: `alice_private.pem`, `alice_public.pem`, `bob_private.pem`, `bob_public.pem`.

### 3. Jalankan Bob terlebih dahulu (sisi penerima)

```bash
# Terminal 1
python bob.py
```

Bob akan standby mendengarkan koneksi masuk di port `9999`.

### 4. Jalankan Alice (sisi pengirim)

```bash
# Terminal 2
python alice.py
```

Alice akan mengeksekusi semua langkah pengamanan lalu mengirim payload ke Bob.

---

### Menjalankan di 2 Komputer Berbeda (Jaringan Lokal)

Jika ingin menjalankan Alice dan Bob di dua mesin berbeda dalam satu jaringan:

1. Jalankan `keygen.py` di masing-masing mesin, lalu tukar file public key:
   - Kirim `alice_public.pem` dari mesin Alice ke mesin Bob.
   - Kirim `bob_public.pem` dari mesin Bob ke mesin Alice.

2. Edit baris berikut di `alice.py` sesuai IP mesin Bob:

```python
BOB_IP = "192.168.1.20"   # ganti ke IP Bob yang sebenarnya
```

3. Jalankan `bob.py` di mesin Bob, lalu `alice.py` di mesin Alice seperti biasa.

## Alur End-to-End

1. **Alice** menyiapkan plaintext.
2. **Alice** membuat AES-256 key dan IV secara acak.
3. **Alice** mengenkripsi plaintext menjadi ciphertext (AES-256-CBC).
4. **Alice** mengenkripsi AES key menjadi `enc_key` (RSA-OAEP).
5. **Alice** membuat hash plaintext (`hash_value`) dengan SHA-256.
6. **Alice** menandatangani hash menjadi `signature` (RSA-PSS).
7. **Alice** mengirim payload JSON ke Bob via TCP socket.
8. **Bob** menerima payload dari IP Alice.
9. **Bob** mendekripsi `enc_key` menjadi AES key (RSA-OAEP).
10. **Bob** mendekripsi ciphertext menjadi plaintext (AES-256-CBC).
11. **Bob** menghitung ulang hash dan membandingkannya dengan hash pada payload.
12. **Bob** memverifikasi `signature` menggunakan public key Alice (RSA-PSS).
13. **Bob** menyimpulkan hasil akhir: valid / tidak valid.

## Format Payload yang Dikirim

Payload dikirim dalam format JSON melalui TCP socket. Berikut struktur lengkapnya:

```json
{
  "source_ip"            : "127.0.0.1",
  "destination_ip"       : "127.0.0.1",
  "ciphertext"           : "<hex>",
  "iv"                   : "<hex>",
  "encrypted_key"        : "<hex>",
  "hash"                 : "<hex SHA-256>",
  "signature"            : "<hex>",
  "hash_algorithm"       : "SHA-256",
  "symmetric_algorithm"  : "AES-256-CBC",
  "asymmetric_algorithm" : "RSA-2048-OAEP",
  "timestamp"            : "YYYY-MM-DD HH:MM:SS"
}
```

## Komponen Kriptografi

| Komponen | Algoritma | Keterangan |
|---|---|---|
| Symmetric Encryption | AES-256-CBC | Mengenkripsi isi pesan. Kunci 256-bit dibuat acak setiap pengiriman. IV 128-bit juga acak dan ikut dikirim dalam payload. |
| Asymmetric Encryption | RSA-2048 + OAEP | Mengenkripsi AES key agar hanya Bob yang bisa membukanya menggunakan private key miliknya. |
| Hash Function | SHA-256 | Dihitung dari plaintext. Bob hitung ulang dan bandingkan untuk memastikan pesan tidak berubah selama transmisi. |
| Digital Signature | RSA-PSS + SHA-256 | Alice menandatangani hash menggunakan private key-nya. Bob verifikasi menggunakan public key Alice untuk memastikan keaslian pengirim. |
| Transport | TCP Socket | Payload JSON dikirim dari IP Alice ke IP Bob. Ukuran payload dikirim terlebih dahulu (4 bytes header) sebelum data utama. |

## Alasan Pemilihan Algoritma

- **AES-256-CBC** dipilih untuk enkripsi simetris karena efisien untuk data berukuran berapapun dan merupakan standar industri yang sudah terbukti aman.
- **RSA-2048 dengan OAEP padding** dipilih untuk enkripsi asimetris karena OAEP lebih aman dibandingkan padding PKCS#1 v1.5 yang lama, dan ukuran 2048-bit sudah memadai untuk kebutuhan akademis.
- **SHA-256** dipilih karena merupakan standar hash yang umum digunakan, menghasilkan digest 256-bit yang tahan terhadap collision attack.
- **RSA-PSS** dipilih untuk digital signature karena PSS (Probabilistic Signature Scheme) lebih aman secara kriptografis dibandingkan skema deterministik seperti PKCS#1 v1.5.

## Checklist Spesifikasi

### Sisi Alice (Pengirim)
- [x] Menentukan plaintext yang akan diamankan
- [x] Membuat kunci simetris AES-256 secara acak
- [x] Mengenkripsi plaintext dengan AES-256-CBC
- [x] Mengenkripsi kunci simetris dengan public key Bob (RSA-OAEP)
- [x] Menghasilkan hash SHA-256 dari plaintext
- [x] Membuat digital signature menggunakan private key Alice (RSA-PSS)
- [x] Mengirim payload dari IP Alice ke IP Bob via TCP socket

### Sisi Bob (Penerima)
- [x] Menerima payload dari IP Alice
- [x] Mendekripsi encrypted symmetric key menggunakan private key Bob
- [x] Mendekripsi ciphertext menggunakan AES key hasil dekripsi
- [x] Menghitung ulang hash dan membandingkannya dengan hash dalam payload
- [x] Memverifikasi digital signature menggunakan public key Alice
- [x] Menyimpulkan apakah pesan valid, integritasnya terjaga, dan benar berasal dari Alice

### Format & Topologi
- [x] Plaintext minimal 1 kalimat utuh
- [x] Payload memuat: ciphertext, encrypted symmetric key, IV, hash, digital signature, source IP, destination IP, timestamp, dan informasi algoritma
- [x] Komunikasi dilakukan antar IP menggunakan TCP socket
- [x] Mendukung 1 komputer (localhost) maupun 2 komputer berbeda (LAN)
