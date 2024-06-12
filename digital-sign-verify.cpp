#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>

using namespace std;

// Generate ECC keys
void generateECCKeys(const string &privateKeyFile, const string &publicKeyFile)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx)
    {
        cerr << "Error creating PKEY context." << endl;
        return;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0)
    {
        cerr << "Error initializing keygen." << endl;
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <= 0)
    {
        cerr << "Error setting curve." << endl;
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        cerr << "Error generating key." << endl;
        EVP_PKEY_CTX_free(pctx);
        return;
    }

    // Save private key to user directory
    FILE *privateKeyFilePtr = fopen(privateKeyFile.c_str(), "wb");
    if (!privateKeyFilePtr)
    {
        cerr << "Error opening private key file." << endl;
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return;
    }
    PEM_write_PrivateKey(privateKeyFilePtr, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(privateKeyFilePtr);

    // Save public key to server directory
    FILE *publicKeyFilePtr = fopen(publicKeyFile.c_str(), "wb");
    if (!publicKeyFilePtr)
    {
        cerr << "Error opening public key file." << endl;
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return;
    }
    PEM_write_PUBKEY(publicKeyFilePtr, pkey);
    fclose(publicKeyFilePtr);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    cout << "ECC keys generated successfully." << endl;
}

// Sign a PDF with ECC private key
bool signPdfECC(const string &privateKeyPath, const string &pdfPath, const string &signaturePath)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    BIO *keyData = BIO_new(BIO_s_file());
    BIO_read_filename(keyData, privateKeyPath.c_str());
    EVP_PKEY *privateKey = PEM_read_bio_PrivateKey(keyData, NULL, NULL, NULL);
    BIO_free(keyData);
    if (!privateKey)
    {
        cerr << "Error reading private key." << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    ifstream pdfFile(pdfPath, ios::binary);
    if (!pdfFile.is_open())
    {
        cerr << "Error opening PDF file." << endl;
        return false;
    }
    vector<unsigned char> pdfContents((istreambuf_iterator<char>(pdfFile)), istreambuf_iterator<char>());
    pdfFile.close();

    SHA256(&pdfContents[0], pdfContents.size(), hash);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_SignInit(mdctx, EVP_sha256());
    EVP_SignUpdate(mdctx, hash, SHA256_DIGEST_LENGTH);

    unsigned int signatureLen = EVP_PKEY_size(privateKey);
    vector<unsigned char> signature(signatureLen);

    if (!EVP_SignFinal(mdctx, &signature[0], &signatureLen, privateKey))
    {
        cerr << "Error signing PDF." << endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(privateKey);
        return false;
    }

    // Save signature to server directory
    ofstream signatureFile(signaturePath, ios::binary);
    if (!signatureFile.is_open())
    {
        cerr << "Error opening signature file." << endl;
        return false;
    }
    signatureFile.write(reinterpret_cast<const char *>(&signature[0]), signatureLen);
    signatureFile.close();

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(privateKey);
    EVP_cleanup();
    ERR_free_strings();

    return true;
}

// Verify the signature of a PDF with ECC public key
bool verifySignatureECC(const string &publicKeyPath, const string &pdfPath, const string &signaturePath)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    BIO *pubData = BIO_new(BIO_s_file());
    if (BIO_read_filename(pubData, publicKeyPath.c_str()) <= 0)
    {
        cerr << "Error opening public key file." << endl;
        BIO_free(pubData);
        return false;
    }
    EVP_PKEY *publicKey = PEM_read_bio_PUBKEY(pubData, NULL, NULL, NULL);
    BIO_free(pubData);
    if (!publicKey)
    {
        cerr << "Error loading public key." << endl;
        return false;
    }

    ifstream pdfFile(pdfPath, ios::binary);
    vector<unsigned char> pdfContents((istreambuf_iterator<char>(pdfFile)), istreambuf_iterator<char>());
    pdfFile.close();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&pdfContents[0], pdfContents.size(), hash);

    ifstream signatureFile(signaturePath, ios::binary);
    vector<unsigned char> signature(istreambuf_iterator<char>(signatureFile), {});
    signatureFile.close();

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, publicKey);
    EVP_DigestVerifyUpdate(mdctx, hash, SHA256_DIGEST_LENGTH);
    int result = EVP_DigestVerifyFinal(mdctx, &signature[0], signature.size());

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(publicKey);
    EVP_cleanup();
    ERR_free_strings();

    return result == 1;
}

void copyFile(const string &sourcePath, const string &destinationPath)
{
    ifstream src(sourcePath, ios::binary);
    ofstream dest(destinationPath, ios::binary);
    dest << src.rdbuf();
}

int main(int argc, char *argv[])
{
    int roles, action;
    string pdfFile;
    do
    {
        cout << "Choose role:\n";
        cout << "1: Seller\n";
        cout << "2: Server\n";
        cout << "3: Buyer\n";
        cout << "4: Exit\n";
        cin >> roles;

        switch (roles)
        {
        case 1:
            cout << "Seller \n";
            do
            {
                cout << "Choose action :\n";
                cout << "1: Generate keys\n";
                cout << "2: Sign pdf file\n";
                cout << "3: Exit\n";
                cin >> action;
                if (action == 1)
                {
                    generateECCKeys("seller/private_key.pem", "server/public_key.pem");
                }
                else if (action == 2)
                {
                    cout << "Seller choose sign file PDF.\n";
                    cout << "Enter pdf file\n";
                    cin >> pdfFile;
                    string pdfPath = "seller/" + pdfFile;
                    string signaturePath = "server/signed_signature.bin";
                    if (signPdfECC("seller/private_key.pem", pdfPath, signaturePath))
                    {
                        copyFile("seller/" + pdfFile, "server/" + pdfFile);
                        cout << "PDF file is signed successfully.\n";
                    }
                    else
                    {
                        cout << "Fail.\n";
                    }
                }
                else if (action == 3)
                {
                    // Exit current role
                    break;
                }
                else
                {
                    cout << "Please choose valid action.\n";
                }
            } while (action != 3);
            break;
        case 2:
            // Code cho (Server)
            cout << "Server \n";
            do
            {
                cout << "Choose action :\n";
                cout << "1: Verify PDF\n";
                cout << "2: Send PDF to Buyer\n";
                cout << "3: Exit\n";
                cin >> action;
                if (action == 1)
                {
                    cout << "Server choose verify PDF.\n";
                    string pdfPath, signaturePath;
                    string pdfCheck;
                    cout << "Enter pdf file need verify\n";
                    cin >> pdfCheck;
                    pdfPath = "seller/" + pdfCheck;
                    signaturePath = "server/signed_signature.bin";
                    if (verifySignatureECC("server/public_key.pem", pdfPath, signaturePath))
                    {
                        cout << "PDF is verified successfully.\n";
                        // Thực hiện lưu file PDF vào server
                        string destinationPath = "server/verified_pdf.pdf";
                        copyFile(pdfPath, destinationPath);
                        cout << "PDF is saved to server.\n";
                    }
                    else
                    {
                        cout << "Fail to verified PDF file.\n";
                    }
                }
                else if (action == 2)
                {
                    cout << "Server sending verified PDF to Buyer.\n";
                    string pdfPath = "server/verified_pdf.pdf";
                    string destinationPath = "buyer/received_pdf.pdf";
                    copyFile(pdfPath, destinationPath);
                    cout << "PDF sent to buyer successfully.\n";
                }
                else if (action == 3)
                {
                    // Exit current role
                    break;
                }
                else
                {
                    cout << "Please choose valid action.\n";
                }
            } while (action != 3);
            break;
        case 3:
            // Code cho (Buyer)
            cout << "Buyer \n";
            do
            {
                cout << "Choose action :\n";
                cout << "1: Generate keys\n";
                cout << "2: Sign file\n";
                cout << "3: Exit\n";
                cin >> action;
                if (action == 1)
                {
                    generateECCKeys("buyer/private_key.pem", "server/public_key.pem");
                }
                else if (action == 2)
                {
                    cout << "Buyer choose sign file PDF.\n";
                    cout << "Enter pdf file\n";
                    cin >> pdfFile;
                    string pdfPath = "buyer/" + pdfFile;
                    string signaturePath = "server/signed_signature.bin";
                    if (signPdfECC("buyer/private_key.pem", pdfPath, signaturePath))
                    {
                        copyFile("buyer/" + pdfFile, "server/" + pdfFile);
                        cout << "PDF file is signed successfully.\n";
                    }
                    else
                    {
                        cout << "Fail.\n";
                    }
                }
                else if (action == 3)
                {
                    // Exit current role
                    break;
                }
                else
                {
                    cout << "Please choose valid action.\n";
                }
            } while (action != 2);
            break;
        case 4:
            // Thoát chương trình
            break;
        default:
            cout << "Please choose valid role.\n";
            break;
        }
    } while (roles != 4);
    return 0;
}