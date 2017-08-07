/**
* Written by: Kyle Xiao
* Date: April 11, 2016
*
* This program will encrypt and decrypt messages using an RSA public key algorithm.
*/
#include <iostream>
#include <fstream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <time.h>
#include <string.h>
#include <math.h>
#include <climits>
#include <boost/multiprecision/cpp_int.hpp>

using namespace std;
using namespace boost::multiprecision;

string user_input;
int1024_t p1, p2, n, m, e, d;
const int1024_t e_bound = 65536;
long r = time(NULL);

/**
* @param s pointer to beginning of c string to be converted into a int1024_t number
* @return converted int1024_t number
*/
int1024_t stoint1024_t(const char * s){
    int1024_t n = 0;
    while( *s != '\0' ) {
        n *= 10;
        n += *s - '0';
        s++;
    }
    return n;
}

/**
* Returns a random int1024_t number
* @return random int1024_t number
*/
int1024_t lrand(){
    ++r;
    srand(r);
    int1024_t num = (int1024_t) rand();
    for(unsigned int i=0; i<25; ++i){
        num *= 10000;
        ++r;
        srand(r);
        num += (int1024_t) rand();
    }
    return num;
}

/**
* PRECONDITION: Arguments are unsigned integers and p > 1
* Raises a number to a power and takes the mod of that result
* @param base base
* @param exp exponent
* @param m modulus
* @return solution
*/
template <typename T>
T modpow(T base, T exp, T m) {
    base %= m;
    T result = 1;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % m;
        base = (base * base) % m;
        exp >>= 1;
    }
    return result%m;
}

/**
* Checks if a number is prime
* @param n number being checked
* @return whether the number is prime
*/
bool isPrime(int1024_t n){
    int1024_t h = (int1024_t) sqrt(n) + 1;
    if(n%2 == 0){
        return false;
    }
    for(int1024_t i=3; i<=h; i+=2){
        if(n % i == 0){
            return false;
        }
    }
    return true;
}

/**
* Quickly checks if a number is prime. Small possibility of error for Carmichael numbers.
* @param n number being checked
* @return whether the number is prime
*/
bool quick_isPrime(int1024_t n){
    if(modpow((int1024_t)3, (int1024_t)n-1, n) == 1){
        return true;
    }
    return false;
}

/**
* Generates a prime number within range specified.
* @param lb lower bound
* @param ub upper bound
* @return a random prime within the bounds specified
*/
int1024_t generate_prime(int1024_t lb, int1024_t ub){
    int1024_t prime;
    prime = ((int1024_t) lrand() % (ub - lb)) + lb;
    if(prime % 2 == 0){
        --prime;
    }
    while(!isPrime(prime)){
        prime -= 2;
        if(prime < lb){
            prime = ub;
        }
    }
    return prime;
}

/**
* Generates a prime number with a limited range in order to compute within a reasonable amount of time.
* @return a random prime
*/
int1024_t generate_prime(){
    return generate_prime((int1024_t) LONG_MAX/4, (int1024_t) LONG_MAX);
}

/**
* Quickly generates a prime number within range specified.
* @param lb lower bound
* @param ub upper bound
* @return a random prime within the bounds specified
*/
int1024_t quick_generate_prime(int1024_t lb, int1024_t ub){
    int1024_t prime;
    prime = ((int1024_t) lrand() % (ub - lb)) + lb;
    if(prime % 2 == 0){
        --prime;
    }
    while(!quick_isPrime(prime)){
        prime -= 2;
        if(prime < lb){
            prime = ub;
        }
    }
    return prime;
}

/**
* Generates a prime number.
* @return a random prime
*/
int1024_t quick_generate_prime(){
    return quick_generate_prime((int1024_t) pow(LLONG_MAX, 3), (int1024_t) pow(LLONG_MAX, 4));
}

/**
* Finds the modular multiplicative inverse
* @param a coefficient
* @param m base
* @return the modular multiplicative inverse
*/
int1024_t mod_inverse(int1024_t a, int1024_t m){
    int1024_t m0 = m, t, q;
    int1024_t x0 = 0, x1 = 1;
    if (m == 1 || m == 0){
      return 0;
    }
    while (a > 1){
        q = a / m;
        t = m;
        m = a % m, a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    // Ensure x1 is positive
    if (x1 < 0){
       x1 += m0;
    }
    return x1;
}

/**
* Encrypts a message using user-specified public key
* @param message message to be encrypted
* @param e exponent of public key
* @param n modulus of public key
* @return encrypted message
*/
vector<int1024_t> encrypt(string message, int1024_t e, int1024_t n){
    vector<int1024_t> cipher_text;
    cipher_text.reserve(message.length());
    for(unsigned long int i=0; i<message.length(); ++i){
        cipher_text.push_back(modpow((int1024_t)message.at(i), e, n));
    }
    return cipher_text;
}

/**
* Encrypts a message using user-specified public key
* @param message encrypted message
* @param d exponent of private key
* @param n modulus of public key
* @return decrypted message
*/
string decrypt(vector<int1024_t> message, int1024_t d, int1024_t n){
    string cipher_text = "";
    for(unsigned long int i=0; i<message.size(); ++i){
        cipher_text += (char)modpow((int1024_t)message.at(i), d, n);
    }
    return cipher_text;
}

/**
* Creates an encryption key
*/
void get_key(){
    //lets user choose whether to input their own prime numbers into the algorithm
    cout << "Would you like to auto generate primes (yes/no)?\n";
    cin >> user_input;
    if(user_input == "yes"){
        cout << "Would you like to set bounds (yes/no)?\n";
        cin >> user_input;
        if(user_input == "yes"){
            int1024_t lb, ub;
            cout << "Lower Bound?\n";
            cin >> user_input;
            lb = stoint1024_t(user_input.c_str());
            cout << "Upper Bound?\n";
            cin >> user_input;
            ub = stoint1024_t(user_input.c_str());
            cout << "Would you like to quickly solve for primes with a small chance of error (not recommended for small numbers)?\n";
            cin >> user_input;
            cout << "Generating primes...\n";
            if(user_input == "yes"){
                //ensures two random, distinct primes
                do{
                    p1 = quick_generate_prime(lb, ub);
                    p2 = quick_generate_prime(lb, ub);
                }while(p1 == p2);
            }else{
                //ensures two random, distinct primes
                do{
                    p1 = generate_prime(lb, ub);
                    p2 = generate_prime(lb, ub);
                }while(p1 == p2);
            }
        }else{
            cout << "Would you like to quickly solve for very large primes with a small chance of error?\n";
            cin >> user_input;
            cout << "Generating primes...\n";
            if(user_input == "yes"){
                //ensures two random, distinct primes
                do{
                    p1 = quick_generate_prime();
                    p2 = quick_generate_prime();
                }while(p1 == p2);
            }else{
                //ensures two random, distinct primes
                do{
                    p1 = generate_prime();
                    p2 = generate_prime();
                }while(p1 == p2);
            }
        }
    }else{
        //gets user input for prime values
        cout << "prime 1=?\n";
        cin >> user_input;
        p1 = stoint1024_t(user_input.c_str());
        cout << "prime 2=?\n";
        cin >> user_input;
        p2 = stoint1024_t(user_input.c_str());
    }
    //calculate n (composite product) and m (totient of n)
    n = p1 * p2;
    m = (p1-1) * (p2-1);
    //lets user choose whether to input e into the algorithm
    cout << "Would you like to auto generate e (yes/no)?\n";
    cin >> user_input;
    time_t timer = time(0);
    if(user_input == "yes"){
        cout << "Generating e value...\n";
        //ensures a coprime e less than e_bound
        do{
            if(difftime(time(0), timer) > 10){
                cout << "Generating New Key...\n";
                p1 = generate_prime();
                p2 = generate_prime();
                n = p1 * p2;
                m = (p1-1) * (p2-1);
                timer = time(0);
            }
            if(m > e_bound){
                e = generate_prime(3, e_bound);
            }else{
                e = generate_prime(3, m);
            }
        }while(m%e == 0);
        d = mod_inverse(e, m);
    }else{
        //gets user input for e value
        cout << "e=?\n";
        cin >> user_input;
        e = stoint1024_t(user_input.c_str());
    }
    cout << "Prime Values: p=" << p1 << " " << "q=" << p2 << "\n";
    cout << "Public Encryption Key: n=" << n << ", e=" << e << "\n";
    cout << "Private Encryption Key: d=" << d << "\n";
}

/**
* Translate message in file into message array
*/
string encrypt_in(){
    ifstream fin("encrypt_in.txt");
    string c = "";
    string s = "";
    while(!fin.eof()){
        getline(fin, c);
        s += c;
        s += "\n";
    }
    fin.close();
    return s;
}

/**
* Write decrypted message into a file
* @param message message to be written
*/
void decrypt_out(string m){
    ofstream fout("decrypt_out.txt");
    fout << m;
    fout.close();
}

/**
* Send encrypted message into a file
* @param message message to be written
*/
void encrypt_out(vector<int1024_t> message){
    ofstream fout("encrypt_out.txt");
    for(unsigned long i=0; i<message.size(); ++i){
        fout << message.at(i) << " ";
    }
    fout.close();
}

/**
* receive encrypted message into a file
* @param message message to be written
* @return message
*/
vector<int1024_t> decrypt_in(){
    ifstream fin("decrypt_in.txt");
    string temp;
    vector<int1024_t> message;
    while(!fin.eof()){
        fin >> temp;
        message.push_back(stoint1024_t(temp.c_str()));
    }
    fin.close();
    return message;
}

/**
* Allows user to input and implement encryption values
*/
void user_encrypt(){
    int1024_t user_e, user_n;
    cout << "e=?\n";
    cin >> user_input;
    user_e = stoint1024_t(user_input.c_str());
    cout << "n=?\n";
    cin >> user_input;
    user_n = stoint1024_t(user_input.c_str());
    cout << "Encrypting...\n";
    encrypt_out(encrypt(encrypt_in(), user_e, user_n));
}

/**
* Allows user to input and implement decryption values
*/
void user_decrypt(){
    int1024_t user_d, user_n;
    cout << "d=?\n";
    cin >> user_input;
    user_d = stoint1024_t(user_input.c_str());
    cout << "n=?\n";
    cin >> user_input;
    user_n = stoint1024_t(user_input.c_str());
    cout << "Decrypting...\n";
    decrypt_out(decrypt(decrypt_in(), user_d, user_n));
}

int main(){
    p1 = p2 = 0;
    e = 2;
    cout << "RSA ENCRYPTION SOFTWARE\n";
    while(true){
        cout << "Enter a command to continue\n";
        cin >> user_input;
        if(user_input == "key"){
            get_key();
        }else if(user_input == "encrypt"){
            if(p1 != 0 && p2 != 0){
                cout << "Would you like to use the generated key (yes/no)?\n";
                cin >> user_input;
                if(user_input == "yes"){
                    cout << "Encrypting...\n";
                    encrypt_out(encrypt(encrypt_in(), e, n));
                }else{
                    user_encrypt();
                }
            }else{
                user_encrypt();
            }
        }else if(user_input == "decrypt"){
            if(p1 != 0 && p2 != 0){
                cout << "Would you like to use the generated key (yes/no)?\n";
                cin >> user_input;
                if(user_input == "yes"){
                    cout << "Decrypting...\n";
                    decrypt_out(decrypt(decrypt_in(), d, n));
                }else{
                    user_decrypt();
                }
            }else{
                user_decrypt();
            }
        }else if(user_input == "prime"){
            cout << generate_prime() << "\n";
        }else if(user_input == "exit"){
            return 0;
        }else{
            cerr << "Invalid Command\n";
        }
    }
    return 0;
}
