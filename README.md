# Kyber Keystore Generator

Kyber Keystore Generator is a tool for generating keystores compatible with the Kyber768 (ML-KEM 768) algorithm. It simplifies the process of managing cryptographic keys used in Kyber-based applications.

## Features

- Generate keypairs for use with the Kyber algorithm.
- Store and manage generated keypairs securely.
- Easily integrate generated keys into Kyber-enabled applications.

## Getting Started

To get started with KyberKeystoreGen, follow these steps:

1. Clone this repository to your local machine:

    ```bash
    git clone https://github.com/hwupathum/kyber-keystore-gen.git
    ```

2. Navigate to the project directory:

    ```bash
    cd kyber-keystore-gen
    ```

3. Build the project using Maven:

    ```bash
    mvn clean install
    ```
4. Use the tool to generate and manage keystores for the Kyber algorithm:

    ```bash
    java -jar target/kyber-keystore-gen-1.0-SNAPSHOT.jar
    ```

5. Enter keystore name, alias, password, and certificate details when prompted.

    ```bash
    Enter keystore name 
    [keystore.p12]: <keystore-name>
    Enter certificate alias 
    [alias]: <alias-name>
    Enter Keystore Password: <password>
    Re-enter new password: <password>
    What is your first and last name?
     [Unknown]: 
    What is the name of your organizational unit?
     [Unknown]: 
    What is the name of your organization?
     [Unknown]: 
    What is the name of your City or Locality?
     [Unknown]: 
    What is the name of your State or Province?
     [Unknown]: 
    What is the two-letter country code for this unit?
     [Unknown]: 
    Is CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown correct?
     [no]: yes
    Key pair and certificate added to Keystore successfully!
    ```
   
6. Use the following command to export the public certificate of the generated keypair:

    ```bash
    keytool -exportcert -alias <alias-name> -keystore <keystore-name> -rfc -file <cert-name>
    ```

## Usage

Provide detailed instructions on how to use KyberKeystoreGen here. Include examples, command-line options, and any other relevant information.

## Contributing

Contributions are welcome! If you'd like to contribute to KyberKeystoreGen, please follow these guidelines:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and ensure they are properly tested.
4. Submit a pull request with a clear description of your changes.

## Support

If you encounter any issues or have questions about KyberKeystoreGen, please [open an issue](https://github.com/your-username/KyberKeystoreGen/issues) on GitHub.
