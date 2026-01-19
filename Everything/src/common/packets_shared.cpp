#include "asio.hpp"
#include "asio/ssl.hpp"
#include "packets_shared.hpp"

#ifdef _SERVER
#include "ssl_server.hpp"
#endif // _SERVER


PROCESS_PACKET(TestPacket)
{
	printf("Processing TestPacket, message: %s\n", Get()->m_Buf);
}

PROCESS_PACKET(MaxPacket)
{
	printf("Processing TestPacket, message: %s\n", &Get()->m_MaxBuf[0]);
}

void ChainFileStream::ProcessStream(bool trl, std::vector<Byte>& vec)
{
#ifdef  _SERVER
	GetSession()->Close();
#else
	if (trl)
	{
		printf("Got chain file of %i bytes\n", vec.size());
        for (const auto& c : vec)
        {
            printf("%c", c);
        }

		asio::post([]()
			{

			});
	}
#endif //  _SERVER
}

void ChainFileRequest::Process()
{
	// TODO: Generate a self-signed certificate and private key, store in ByteVector    
    //       The goal is to have a sign up system for the client
    //       with optionally a paywall, where clients could request a cerificate
	//       upon creating an account.
#ifdef  _SERVER
	asio::post([this]()
		{
            ByteVector vecFile;
            {
                // Step 1: Generate RSA Key
                RSA* rsa_key = RSA_new();
                BIGNUM* bn = BN_new();
                BN_set_word(bn, RSA_F4);  // Public exponent 65537
                if (!RSA_generate_key_ex(rsa_key, 2048, bn, NULL)) {
                    fprintf(stderr, "Failed to generate RSA key\n");
                    return -1;
                }

                // Step 2: Create EVP key structure
                EVP_PKEY* pkey = EVP_PKEY_new();
                if (!EVP_PKEY_assign_RSA(pkey, rsa_key)) {
                    fprintf(stderr, "Failed to assign RSA key\n");
                    return -1;
                }

                // Step 3: Create X509 certificate structure
                X509* x509 = X509_new();
                if (!x509) {
                    fprintf(stderr, "Failed to create X509 structure\n");
                    return -1;
                }

                // Step 4: Set validity period (365 days)
                X509_gmtime_adj(X509_get_notBefore(x509), 0);           // Start time: Now
                X509_gmtime_adj(X509_get_notAfter(x509), 30 * 86400);  // End time: 30 days from now

                // Step 5: Set the public key for the certificate
                X509_set_pubkey(x509, pkey);

                // Step 6: Sign the certificate with the private key
                if (!X509_sign(x509, pkey, EVP_sha256())) {
                    fprintf(stderr, "Failed to sign the certificate\n");
                    return -1;
                }

                // Step 7: Write both the certificate and private key to a memory buffer (BIO)
                BIO* mem_bio = BIO_new(BIO_s_mem());

                // Write the certificate to the memory buffer
                if (!PEM_write_bio_X509(mem_bio, x509)) {
                    fprintf(stderr, "Failed to write certificate to memory buffer\n");
                    return -1;
                }

                // Write the private key to the memory buffer
                if (!PEM_write_bio_PrivateKey(mem_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
                    fprintf(stderr, "Failed to write private key to memory buffer\n");
                    return -1;
                }

                // Step 8: Copy the certificate and key from memory buffer to vector
                char* data;
                long data_len = BIO_get_mem_data(mem_bio, &data);
                vecFile.assign(data, data + data_len);

                // Clean up
                BIO_free(mem_bio);
                EVP_PKEY_free(pkey);
                X509_free(x509);
                BN_free(bn);

            }

            // Print vector size to verify the certificate was stored
            printf("Certificate stored in vector. Size: %i bytes", vecFile.size());

            PACKET(ChainFileStream, s);
            GetSession()->Stream(vecFile, s);
		});
#endif //  _SERVER
}

PROCESS_PACKET(ChatPacket)
{
#ifdef _SERVER
	GetSession( )->GetServer( )->Multicast( std::shared_ptr<IPacket>(this) );
#else
	printf("%s: %s\n", Get()->m_Username, Get()->m_Line);
#endif // _SERVER
}
