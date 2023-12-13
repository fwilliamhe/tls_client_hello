/*
 Copyright (c) 2023 William He (w.he@fwilliam.net)

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <brotli/decode.h>

using boost::asio::ip::tcp;
using std::placeholders::_1;
using std::placeholders::_2;

enum {
    max_length = 1024
};



std::string SNI;
namespace ChromeEnv {
    namespace BrotilDecoder {
        int DecompressBrotliCert(SSL *ssl,
                         CRYPTO_BUFFER **out,
                         size_t uncompressed_len,
                         const uint8_t *in,
                         size_t in_len)
        {
            uint8_t *data;
            bssl::UniquePtr<CRYPTO_BUFFER> decompressed(
                CRYPTO_BUFFER_alloc(&data, uncompressed_len));
            if (!decompressed)
            {
                return 0;
            }

            size_t output_size = uncompressed_len;
            if (BrotliDecoderDecompress(in_len, in, &output_size, data) !=
                    BROTLI_DECODER_RESULT_SUCCESS ||
                output_size != uncompressed_len)
            {
                return 0;
            }

            *out = decompressed.release();
            return 1;
        }
    }
    bool init_ssl(SSL* handle) {
        // SNI
        SSL_set_tlsext_host_name(handle, SNI.c_str());

        // chromium ssl_client_socket_impl.cc : 873 
        unsigned char app_settings_protos[] = {'h', '2'};
        if (!SSL_add_application_settings(handle, app_settings_protos, sizeof(app_settings_protos), nullptr, 0))
            return false;

        // chromium ssl_client_socket_impl.cc : 889
        SSL_set_renegotiate_mode(handle, ssl_renegotiate_explicit);
        
        // chromium ssl_client_socket_impl.cc : 891
        SSL_set_shed_handshake_config(handle, 1);

        // ECH
        SSL_set_enable_ech_grease(handle, 1);
        // if (!SSL_set1_ech_config_list(handle, ech_config_list, ech_config_list_len)) 
        //     return false;
        return true;
    }
    SSL_CTX* create_ctx() { 
        SSL_CTX *hCTX = ::SSL_CTX_new(::TLS_client_method());
        SSL_CTX_set_min_proto_version(hCTX, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(hCTX, TLS1_3_VERSION);

        // chromium ssl_client_socket_impl.cc : 298
        SSL_CTX_set_reverify_on_resume(hCTX, 1);
        if (!SSL_CTX_add_cert_compression_alg(hCTX, TLSEXT_cert_compression_brotli, nullptr, BrotilDecoder::DecompressBrotliCert)) {
            std::cerr << "SSL_CTX_add_cert_compression_alg failed!" << '\n';
            return nullptr;
        }
        
        // chromium ssl_client_socket_impl.cc : 919
        SSL_CTX_set_permute_extensions(hCTX, 1);
        
        // chromium ssl_client_socket_impl.cc : 308
        SSL_CTX_set_grease_enabled(hCTX, 1);
        
        // chromium ssl_client_socket_impl.cc : 843
        if (!SSL_CTX_set_cipher_list(hCTX, "ALL:!aPSK:!ECDSA+SHA1:!3DES")) {
            std::cerr << "SSL_CTX_set_cipher_list failed!" << '\n';
            return nullptr;
        }

        SSL_CTX_set_options(hCTX, SSL_OP_NO_COMPRESSION);

        SSL_CTX_enable_signed_cert_timestamps(hCTX);
        SSL_CTX_enable_ocsp_stapling(hCTX);

        
        unsigned char protos[] = {2, 'h', '2',
                                  8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

        // !!! Pay attention to the unusual return value of this function !!!
        if (SSL_CTX_set_alpn_protos(hCTX, protos, sizeof(protos))) {
            std::cerr << "SSL_CTX_set_alpn_protos failed!" << '\n';
            return false;
        }

        static const uint16_t kVerifyPrefs[] = {
            SSL_SIGN_ECDSA_SECP256R1_SHA256,
            SSL_SIGN_RSA_PSS_RSAE_SHA256,
            SSL_SIGN_RSA_PKCS1_SHA256,
            SSL_SIGN_ECDSA_SECP384R1_SHA384,
            SSL_SIGN_RSA_PSS_RSAE_SHA384,
            SSL_SIGN_RSA_PKCS1_SHA384,
            SSL_SIGN_RSA_PSS_RSAE_SHA512,
            SSL_SIGN_RSA_PKCS1_SHA512,
        };
        if (!SSL_CTX_set_verify_algorithm_prefs(hCTX, kVerifyPrefs, std::size(kVerifyPrefs))) {
            std::cerr << "SSL_CTX_set_verify_algorithm_prefs failed!" << '\n';
            return nullptr;
        }
        return hCTX;
    }

}


class client {
public:
    client(boost::asio::io_context &io_context,
           boost::asio::ssl::context &context,
           const tcp::resolver::results_type &endpoints)
        : socket_(io_context, context)
    {
        ChromeEnv::init_ssl(socket_.native_handle());
        socket_.set_verify_mode(boost::asio::ssl::verify_peer);
        socket_.set_verify_callback(
            std::bind(&client::verify_certificate, this, _1, _2));
        connect(endpoints);
    }

private:
    bool verify_certificate(bool preverified,
                            boost::asio::ssl::verify_context &ctx)
    {
        char subject_name[256];
        X509 *cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
        std::cout << "Verifying " << subject_name << "\n";

        return preverified;
    }

    void connect(const tcp::resolver::results_type &endpoints)
    {
        boost::asio::async_connect(socket_.lowest_layer(), endpoints,
                                   [this](const boost::system::error_code &error,
                                          const tcp::endpoint & /*endpoint*/)
                                   {
                                       if (!error)
                                       {
                                           handshake();
                                       }
                                       else
                                       {
                                           std::cout << "Connect failed: " << error.message() << "\n";
                                       }
                                   });
    }

    void handshake()
    {
        socket_.async_handshake(boost::asio::ssl::stream_base::client,
                                [this](const boost::system::error_code &error)
                                {
                                    if (!error)
                                    {
                                        send_request();
                                    }
                                    else
                                    {
                                        std::cout << "Handshake failed: " << error.message() << "\n";
                                    }
                                });
    }

    void send_request()
    {
        std::cout << "Enter message: ";
        std::cin.getline(request_, max_length);
        size_t request_length = std::strlen(request_);

        boost::asio::async_write(socket_,
                                 boost::asio::buffer(request_, request_length),
                                 [this](const boost::system::error_code &error, std::size_t length)
                                 {
                                     if (!error)
                                     {
                                         receive_response(length);
                                     }
                                     else
                                     {
                                         std::cout << "Write failed: " << error.message() << "\n";
                                     }
                                 });
    }

    void receive_response(std::size_t length)
    {
        boost::asio::async_read(socket_,
                                boost::asio::buffer(reply_, length),
                                [this](const boost::system::error_code &error, std::size_t length)
                                {
                                    if (!error)
                                    {
                                        std::cout << "Reply: ";
                                        std::cout.write(reply_, length);
                                        std::cout << "\n";
                                    }
                                    else
                                    {
                                        std::cout << "Read failed: " << error.message() << "\n";
                                    }
                                });
    }
    boost::asio::ssl::stream<tcp::socket> socket_;
    char request_[max_length];
    char reply_[max_length];
};



int main(int argc, char *argv[])
{
    OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, nullptr);
    try
    {
        if (argc != 3)
        {
            std::cerr << "Usage: client <host> <port>\n";
            return 1;
        }
        SNI = std::string(argv[1]);
        boost::asio::io_context io_context;
        tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(argv[1], argv[2]);
        std::cout << "Solve to -> " << endpoints->endpoint() << '\n';

        boost::asio::ssl::context ctx(ChromeEnv::create_ctx());
        client c(io_context, ctx, endpoints);
        io_context.run();
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}