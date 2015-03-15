/*
 * sig_client.c
 *
 * Author: Alec Guertin
 * University of California, Berkeley
 * CS 161 - Computer Security
 * Fall 2014 Semester
 * Project 1
 */

#include "client.h"
/* The file descriptor for the socket connected to the server. */
static int sockfd;

static void perform_rsa(mpz_t result, mpz_t message, mpz_t d, mpz_t n);
static int hex_to_ascii(char a, char b);
static int hex_to_int(char a);
static void hex_to_binary(char hex[]);
void set_binary(unsigned char value, int index);
static void usage();
static void kill_handler(int signum);
static int random_int();
static void cleanup();
static unsigned char ms_encryption[16];

int main(int argc, char **argv) {
  int err, option_index, c, clientlen, counter;
  unsigned char rcv_plaintext[AES_BLOCK_SIZE];
  unsigned char rcv_ciphertext[AES_BLOCK_SIZE];
  unsigned char send_plaintext[AES_BLOCK_SIZE];
  unsigned char send_ciphertext[AES_BLOCK_SIZE];
  aes_context enc_ctx, dec_ctx;
  in_addr_t ip_addr;
  struct sockaddr_in server_addr;
  FILE *c_file, *d_file, *m_file;
  ssize_t read_size, write_size;
  struct sockaddr_in client_addr;
  tls_msg err_msg, send_msg, rcv_msg;
  mpz_t client_exp, client_mod;
  fd_set readfds;
  struct timeval tv;

  c_file = d_file = m_file = NULL;

  mpz_init(client_exp);
  mpz_init(client_mod);

  /*
   * This section is networking code that you don't need to worry about.
   * Look further down in the function for your part.
   */

  memset(&ip_addr, 0, sizeof(in_addr_t));

  option_index = 0;
  err = 0;

  static struct option long_options[] = {
    {"ip", required_argument, 0, 'i'},
    {"cert", required_argument, 0, 'c'},
    {"exponent", required_argument, 0, 'd'},
    {"modulus", required_argument, 0, 'm'},
    {0, 0, 0, 0},
  };

  while (1) {
    c = getopt_long(argc, argv, "c:i:d:m:", long_options, &option_index);
    if (c < 0) {
      break;
    }
    switch(c) {
    case 0:
      usage();
      break;
    case 'c':
      c_file = fopen(optarg, "r");
      if (c_file == NULL) {
	perror("Certificate file error");
	exit(1);
      }
      break;
    case 'd':
      d_file = fopen(optarg, "r");
      if (d_file == NULL) {
	perror("Exponent file error");
	exit(1);
      }
      break;
    case 'i':
      ip_addr = inet_addr(optarg);
      break;
    case 'm':
      m_file = fopen(optarg, "r");
      if (m_file == NULL) {
	perror("Modulus file error");
	exit(1);
      }
      break;
    case '?':
      usage();
      break;
    default:
      usage();
      break;
    }
  }

  if (d_file == NULL || c_file == NULL || m_file == NULL) {
    usage();
  }
  if (argc != 9) {
    usage();
  }

  mpz_inp_str(client_exp, d_file, 0);
  mpz_inp_str(client_mod, m_file, 0);

  signal(SIGTERM, kill_handler);

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Could not open socket");
    exit(1);
  }

  memset(&server_addr, 0, sizeof(struct sockaddr_in));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = ip_addr;
  server_addr.sin_port = htons(HANDSHAKE_PORT);
  err = connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));
  if (err < 0) {
    perror("Could not bind socket");
    cleanup();
  }

  // YOUR CODE HERE
  // IMPLEMENT THE TLS HANDSHAKE
  //client send hello
    hello_message *hello_msg;
    hello_msg= (hello_message *)malloc(sizeof(hello_message));
    hello_msg->type=CLIENT_HELLO;
    hello_msg->random=random_int();
    hello_msg->cipher_suite=TLS_RSA_WITH_AES_128_ECB_SHA256;
    send_tls_message(sockfd, hello_msg, HELLO_MSG_SIZE);
    
    //store client_random
    int client_random = hello_msg->random;
   
  // client receive a message, check type, if correct type, store hello_message to specific pointer
    hello_message *receive_hello;
    //memset(receive_hello, 0, HELLO_MSG_SIZE);
    receive_hello= (hello_message *)malloc(sizeof(hello_message));
    int err_code= receive_tls_message(sockfd, receive_hello, HELLO_MSG_SIZE, SERVER_HELLO);
    if (err_code!=0){
        cleanup();
    }
    //store server_random
    int server_random=receive_hello->random;
   
    // memset memory to all 0
    cert_message *client_cert;
    client_cert= (cert_message *)malloc(sizeof(cert_message));

    //rend c_file
    memset(client_cert->cert, 0, RSA_MAX_LEN);
    fread(client_cert->cert, RSA_MAX_LEN, 1, c_file);
    client_cert->type=CLIENT_CERTIFICATE;
    
    //client send client certifficate
    send_tls_message(sockfd, client_cert, CERT_MSG_SIZE);

    //client receive server certificate message
    cert_message *receive_cert;
    receive_cert= (cert_message *)malloc(sizeof(cert_message));
    //memset(receive_cert, 0, CERT_MSG_SIZE);
    err_code= receive_tls_message(sockfd, receive_cert, CERT_MSG_SIZE, SERVER_CERTIFICATE);
    
    if (err_code!=0){
      cleanup();
    }
    
    //decript received server certificate
    mpz_t result, e, n;
    mpz_init(result);
    mpz_init(e);
    mpz_init(n);
    mpz_set_str (e, CA_EXPONENT, 0);
    mpz_set_str (n, CA_MODULUS, 0);
    decrypt_cert(result,receive_cert, e, n);

    char cert_plaintext[RSA_MAX_LEN];
    mpz_get_ascii(cert_plaintext, result);
 
    mpz_t server_exponent;
    mpz_init(server_exponent);
    mpz_t server_mod;
    mpz_init(server_mod);
    if (get_cert_exponent(server_exponent, cert_plaintext) == ERR_FAILURE) {
      perror("Cannot get server cert exponent"); cleanup();
    }
    if (get_cert_modulus(server_mod, cert_plaintext) == ERR_FAILURE) {
      perror("Cannot get server cert modulus"); cleanup();
    }

    
    //compute premaster secret
    mpz_t ps_random, ps_m;
    int p_secret_int = random_int();
  
    mpz_init(ps_random);
    mpz_add_ui(ps_random, ps_random, p_secret_int);
    mpz_init(ps_m);
    perform_rsa(ps_m, ps_random, server_exponent,  server_mod);
    char ps_content[RSA_MAX_LEN];
    //ps_content=(char *)malloc(sizeof(RSA_MAX_LEN));
    mpz_get_str(ps_content, HEX_BASE, ps_m);
    ps_msg *ps;
    ps= (ps_msg *)malloc(sizeof(ps_msg));
    ps->type=PREMASTER_SECRET;
    memset(ps->ps, 0, RSA_MAX_LEN);
    strncpy(ps->ps, ps_content, RSA_MAX_LEN);
    // send premaster secret 
    send_tls_message(sockfd, ps, PS_MSG_SIZE);

    //receive server's master secret message 
    ps_msg *receive_ms;
    receive_ms= (ps_msg *)malloc(sizeof(ps_msg));
    //memset(receive_cert, 0, CERT_MSG_SIZE);
    err_code= receive_tls_message(sockfd, receive_ms, PS_MSG_SIZE, VERIFY_MASTER_SECRET);
    if (err_code!=0){
        cleanup();
    }

    

  
    mpz_t computed_master_secret_mtz;
    mpz_init(computed_master_secret_mtz);
   
    mpz_t decrypted_master_secret;
    mpz_init(decrypted_master_secret);
    decrypt_verify_master_secret(decrypted_master_secret, receive_ms, client_exp, client_mod);
    
    unsigned char computed_master_secret[RSA_MAX_LEN];

    compute_master_secret(p_secret_int, client_random, server_random, computed_master_secret);
    unsigned char *ms_content;

    ms_content=hex_to_str(computed_master_secret,16);
    hex_to_binary(ms_content);
    mpz_set_str(computed_master_secret_mtz,ms_content,16);

    int outcome;
    
    outcome=mpz_cmp(computed_master_secret_mtz,decrypted_master_secret);
    
  /*
   * START ENCRYPTED MESSAGES
   */

  memset(send_plaintext, 0, AES_BLOCK_SIZE);
  memset(send_ciphertext, 0, AES_BLOCK_SIZE);
  memset(rcv_plaintext, 0, AES_BLOCK_SIZE);
  memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);

  memset(&rcv_msg, 0, TLS_MSG_SIZE);

  aes_init(&enc_ctx);
  aes_init(&dec_ctx);
  
  // YOUR CODE HERE
  // SET AES KEYS

   aes_setkey_enc(&enc_ctx,ms_encryption,128);
   aes_setkey_dec(&dec_ctx,ms_encryption,128);

  fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
  /* Send and receive data. */
  while (1) {
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(sockfd, &readfds);
    tv.tv_sec = 2;
    tv.tv_usec = 10;

    select(sockfd+1, &readfds, NULL, NULL, &tv);
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      counter = 0;
      memset(&send_msg, 0, TLS_MSG_SIZE);
      send_msg.type = ENCRYPTED_MESSAGE;
      memset(send_plaintext, 0, AES_BLOCK_SIZE);
      read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      while (read_size > 0 && counter + AES_BLOCK_SIZE < TLS_MSG_SIZE - INT_SIZE) {
	if (read_size > 0) {
	  err = aes_crypt_ecb(&enc_ctx, AES_ENCRYPT, send_plaintext, send_ciphertext);
	  memcpy(send_msg.msg + counter, send_ciphertext, AES_BLOCK_SIZE);
	  counter += AES_BLOCK_SIZE;
	}
	memset(send_plaintext, 0, AES_BLOCK_SIZE);
	read_size = read(STDIN_FILENO, send_plaintext, AES_BLOCK_SIZE);
      }
      write_size = write(sockfd, &send_msg, INT_SIZE+counter+AES_BLOCK_SIZE);
      if (write_size < 0) {
	perror("Could not write to socket");
	cleanup();
      }
    } else if (FD_ISSET(sockfd, &readfds)) {
      memset(&rcv_msg, 0, TLS_MSG_SIZE);
      memset(rcv_ciphertext, 0, AES_BLOCK_SIZE);
      read_size = read(sockfd, &rcv_msg, TLS_MSG_SIZE);
      if (read_size > 0) {
	if (rcv_msg.type != ENCRYPTED_MESSAGE) {
	  goto out;
	}
	memcpy(rcv_ciphertext, rcv_msg.msg, AES_BLOCK_SIZE);
	counter = 0;
	while (counter < read_size - INT_SIZE - AES_BLOCK_SIZE) {
	  aes_crypt_ecb(&dec_ctx, AES_DECRYPT, rcv_ciphertext, rcv_plaintext);
	  printf("%s", rcv_plaintext);
	  counter += AES_BLOCK_SIZE;
	  memcpy(rcv_ciphertext, rcv_msg.msg+counter, AES_BLOCK_SIZE);
	}
	printf("\n");
      }
    }

  }

 out:
  close(sockfd);
  return 0;
}

/*
 * \brief                  Decrypts the certificate in the message cert.
 *
 * \param decrypted_cert   This mpz_t stores the final value of the binary
 *                         for the decrypted certificate. Write the end
 *                         result here.
 * \param cert             The message containing the encrypted certificate.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the certificate.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the certificate.
 */
void
decrypt_cert(mpz_t decrypted_cert, cert_message *cert, mpz_t key_exp, mpz_t key_mod)
{
  // YOUR CODE HERE
    char *message = cert->cert;
    mpz_t m;
    mpz_set_str(m, message, 0);
    perform_rsa(decrypted_cert, m, key_exp, key_mod);
    
}

/*
 * \brief                  Decrypts the master secret in the message ms_ver.
 *
 * \param decrypted_ms     This mpz_t stores the final value of the binary
 *                         for the decrypted master secret. Write the end
 *                         result here.
 * \param ms_ver           The message containing the encrypted master secret.
 * \param key_exp          The exponent of the public key for decrypting
 *                         the master secret.
 * \param key_mod          The modulus of the public key for decrypting
 *                         the master secret.
 */
void
decrypt_verify_master_secret(mpz_t decrypted_ms, ps_msg *ms_ver, mpz_t key_exp, mpz_t key_mod)
{
  // YOUR CODE HERE
  
    char *message = ms_ver->ps;
    mpz_t m;
    mpz_init(m);
    mpz_set_str(m, message, 16);
    perform_rsa(decrypted_ms, m, key_exp, key_mod);
    
}

/*
 * \brief                  Computes the master secret.
 *
 * \param ps               The premaster secret.
 * \param client_random    The random value from the client hello.
 * \param server_random    The random value from the server hello.
 * \param master_secret    A pointer to the final value of the master secret.
 *                         Write the end result here.
 */
void
compute_master_secret(int ps, int client_random, int server_random, unsigned char *master_secret)
{
  // YOUR CODE HERE

  
    SHA256_CTX ctx;
    sha256_init(&ctx);
    void *ptr1 = (int *)malloc(sizeof(int));
    ptr1=&ps; 
    void *ptr2 = (int *)malloc(sizeof(int));
    ptr2=&client_random;
    void *ptr3 = (int *)malloc(sizeof(int));
    ptr3=&server_random;
    sha256_update(&ctx, ptr1, sizeof(ps));
    sha256_update(&ctx, ptr2, sizeof(client_random));
    sha256_update(&ctx, ptr3, sizeof(server_random));
    sha256_update(&ctx, ptr1, sizeof(ps));
    sha256_final(&ctx, master_secret);
}

/*
 * \brief                  Sends a message to the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to send
 *                         the message on.
 * \param msg              A pointer to the message to send.
 * \param msg_len          The length of the message in bytes.
 */
int
send_tls_message(int socketno, void *msg, int msg_len)
{
  // YOUR CODE HERE
    write(socketno, msg, msg_len);
}

/*
 * \brief                  Receieves a message from the connected server.
 *                         Returns an error code.
 *
 * \param socketno         A file descriptor for the socket to receive
 *                         the message on.
 * \param msg              A pointer to where to store the received message.
 * \param msg_len          The length of the message in bytes.
 * \param msg_type         The expected type of the message to receive.
 */
int
receive_tls_message(int socketno, void *msg, int msg_len, int msg_type)
{
  // YOUR CODE HERE
    
    if (read(socketno,msg,msg_len) != msg_len) {
        return ERR_FAILURE; 
      }
    if (msg_type==*((int * )msg)){
        return ERR_OK;}
    else{
        return ERR_FAILURE;}
    
}


/*
 * \brief                Encrypts/decrypts a message using the RSA algorithm.
 *
 * \param result         a field to populate with the result of your RSA calculation.
 * \param message        the message to perform RSA on. (probably a cert in this case)
 * \param e              the encryption key from the key_file passed in through the
 *                       command-line arguments
 * \param n              the modulus for RSA from the modulus_file passed in through
 *                       the command-line arguments
 *
 * Fill in this function with your proj0 solution or see staff solutions.
 */
static void
perform_rsa(mpz_t result, mpz_t message, mpz_t e, mpz_t n)
{
    int odd_num;
    
    mpz_set_str(result, "1", 10);
    odd_num = mpz_odd_p(e);
    while (mpz_cmp_ui(e, 0) > 0) {
        if (odd_num) {
            mpz_mul(result, result, message);
            mpz_mod(result, result, n);
            mpz_sub_ui(e, e, 1);
        }
        mpz_mul(message, message, message);
        mpz_mod(message, message, n);
        mpz_div_ui(e, e, 2);
        odd_num = mpz_odd_p(e);
    }
}


/* Returns a pseudo-random integer. */
static int
random_int()
{
  srand(time(NULL));
  return rand();
}

/*
 * \brief                 Returns ascii string from a number in mpz_t form.
 *
 * \param output_str      A pointer to the output string.
 * \param input           The number to convert to ascii.
 */
void
mpz_get_ascii(char *output_str, mpz_t input)
{
  int i,j;
  char *result_str;
  result_str = mpz_get_str(NULL, HEX_BASE, input);
  i = 0;
  j = 0;
  while (result_str[i] != '\0') {
    output_str[j] = hex_to_ascii(result_str[i], result_str[i+1]);
    j += 1;
    i += 2;
  }
}

/*
 * \brief                  Returns a pointer to a string containing the
 *                         characters representing the input hex value.
 *
 * \param data             The input hex value.
 * \param data_len         The length of the data in bytes.
 */
char
*hex_to_str(char *data, int data_len)
{
  int i;
  char *output_str = calloc(1+2*data_len, sizeof(char));
  for (i = 0; i < data_len; i += 1) {
    snprintf(output_str+2*i, 3, "%02X", (unsigned int) (data[i] & 0xFF));
  }
  return output_str;
}

/* Return the public key exponent given the decrypted certificate as string. */
int
get_cert_exponent(mpz_t result, char *cert)
{
  int err;
  char *srch, *srch2;
  char exponent[RSA_MAX_LEN/2];
  memset(exponent, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, ':');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 2;
  srch2 = strchr(srch, '\n');
  if (srch2 == NULL) {
    return ERR_FAILURE;
  }
  strncpy(exponent, srch, srch2-srch);
  err = mpz_set_str(result, exponent, 0);
  if (err == -1) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}

/* Return the public key modulus given the decrypted certificate as string. */
int
get_cert_modulus(mpz_t result, char *cert)
{
  int err;
  char *srch, *srch2;
  char modulus[RSA_MAX_LEN/2];
  memset(modulus, 0, RSA_MAX_LEN/2);
  srch = strchr(cert, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, '\n');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 1;
  srch = strchr(srch, ':');
  if (srch == NULL) {
    return ERR_FAILURE;
  }
  srch += 2;
  srch2 = strchr(srch, '\n');
  if (srch2 == NULL) {
    return ERR_FAILURE;
  }
  strncpy(modulus, srch, srch2-srch);
  err = mpz_set_str(result, modulus, 0);
  if (err == -1) {
    return ERR_FAILURE;
  }
  return ERR_OK;
}

/* Prints the usage string for this program and exits. */
static void
usage()
{
    printf("./client -i <server_ip_address> -c <certificate_file> -m <modulus_file> -d <exponent_file>\n");
    exit(1);
}

/* Catches the signal from C-c and closes connection with server. */
static void
kill_handler(int signum)
{
  if (signum == SIGTERM) {
    cleanup();
  }
}

/* Converts the two input hex characters into an ascii char. */
static int
hex_to_ascii(char a, char b)
{
    int high = hex_to_int(a) * 16;
    int low = hex_to_int(b);
    return high + low;
}

/* Converts a hex value into an int. */
static int
hex_to_int(char a)
{
    if (a >= 97) {
	a -= 32;
    }
    int first = a / 16 - 3;
    int second = a % 16;
    int result = first*10 + second;
    if (result > 9) {
	result -= 1;
    }
    return result;
}

static void hex_to_binary(char hex[])   /* Function to convert hexadecimal to binary. */
{
  int i=0;
  memset(ms_encryption, 0, 16);
while(i<32){
         switch(hex[i]){
             case '0': set_binary(0, i); break;
             case '1': set_binary(1, i); break;
             case '2': set_binary(2, i); break;
             case '3': set_binary(3, i); break;
             case '4': set_binary(4, i); break;
             case '5': set_binary(5, i); break;
             case '6': set_binary(6, i); break;
             case '7': set_binary(7, i); break;
             case '8': set_binary(8, i); break;
             case '9': set_binary(9, i); break;
             case 'A': set_binary(10,i); break;
             case 'B': set_binary(11,i); break;
             case 'C': set_binary(12,i); break;
             case 'D': set_binary(13,i); break;
             case 'E': set_binary(14,i); break;
             case 'F': set_binary(15,i); break;
             case 'a': set_binary(10,i); break;
             case 'b': set_binary(11,i); break;
             case 'c': set_binary(12,i); break;
             case 'd': set_binary(13,i); break;
             case 'e': set_binary(14,i); break;
             case 'f': set_binary(15,i); break;
             default:  printf("\nInvalid hex digit %c ",hex[i]); break;
         }
         i++;
    }
}

void set_binary(unsigned char value, int index) {
  if (index % 2 == 0) {
    ms_encryption[index/2] = value*16;
  } else {
    ms_encryption[index/2] += value;
  }
}

/* Closes files and exits the program. */
static void
cleanup()
{
  close(sockfd);
  exit(1);
}
