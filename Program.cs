namespace KeyVaultPlay
{
    using System;
    using Microsoft.Azure.KeyVault;
    using Microsoft.Azure.Services.AppAuthentication;
    using System.Security.Cryptography;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Linq;
    using Microsoft.Azure.KeyVault.WebKey;
    using System.IO;

    class Program
    {
        private static KeyVaultClient keyVaultClient;
        private static string keyVaultUrl = "https://frans-keyvault-test.vault.azure.net/";
        private static string keyName = "GeneralTestKey";
        static void Main(string[] args)
        {
            var tokenProvider = new AzureServiceTokenProvider();
            keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(tokenProvider.KeyVaultTokenCallback));
            CreateKeyIfNotExists().Wait();
            // SignAndVerify().Wait();
            EncryptAndWrap().Wait();
        }

        private static async Task CreateKeyIfNotExists()
        {
            var versions = await keyVaultClient.GetKeyVersionsAsync(keyVaultUrl, keyName);
            // var existingKey = await keyVaultClient.GetKeyAsync(keyVaultUrl, keyVaultUrl, new CancellationToken());
            if (!versions.Any()) 
            {
                await keyVaultClient.CreateKeyAsync(keyVaultUrl, keyName, "RSA", 2048);
            }
        }

        /// <summary>
        /// Use symmetric encryption, then wrap the key using Key Vault
        /// </summary>
        /// <returns></returns>
        private static async Task EncryptAndWrap()
        {
            // In real-world, these could be concatenated and stored.
            byte[] iv;
            byte[] wrappedKey;
            Stream encryptedData = new MemoryStream();
            string wrappingKeyIdentifier;
            string keyWrappingEncryptionAlgorithm = JsonWebKeyEncryptionAlgorithm.RSA15;

            // TODO: This (probably) doesn't use "AE" - update accordingly.

            // This creates a random key and initialisation vector (IV) and encrypts the data
            using (var encryptingAes = Aes.Create())
            {
                iv = encryptingAes.IV;
                var encryptor = encryptingAes.CreateEncryptor();
                using (var encryptingStream = new CryptoStream(encryptedData, encryptor, CryptoStreamMode.Write, true)) 
                using (var writer = new StreamWriter(encryptingStream)) // NOTE: This is a text writer! Shouldn't do this if we're dealing with binary data!
                {
                    writer.Write(inputText);
                    writer.Flush();
                    encryptingStream.Flush();
                }
                var wrappingResult = await keyVaultClient.WrapKeyAsync($"{keyVaultUrl}keys/{keyName}", keyWrappingEncryptionAlgorithm, encryptingAes.Key);
                wrappedKey = wrappingResult.Result;
                wrappingKeyIdentifier = wrappingResult.Kid;
                // TODO: Test if "wrap" and "encrypt" produce the same resul;t
                var encryptTest = await keyVaultClient.EncryptAsync($"{keyVaultUrl}keys/{keyName}", keyWrappingEncryptionAlgorithm, encryptingAes.Key);
            }

            encryptedData.Position = 0;

            // Decrypt
            var unwrapKeyResult = await keyVaultClient.UnwrapKeyAsync(wrappingKeyIdentifier, keyWrappingEncryptionAlgorithm, wrappedKey);
            var symmetricKey = unwrapKeyResult.Result;
            string decrypted;
            using (var decryptingAes = Aes.Create()) 
            {
               decryptingAes.IV = iv;
               decryptingAes.Key = symmetricKey;
               var decryptor = decryptingAes.CreateDecryptor();
               
               using (var decryptingStream = new CryptoStream(encryptedData, decryptor, CryptoStreamMode.Read))
               using (var reader = new StreamReader(decryptingStream))
               {
                   decrypted = reader.ReadToEnd();
               }
            }

            if (inputText != decrypted)
            {
                throw new Exception("Decrypted does not match encrypted");
            }
        }

        private static async Task SignAndVerify() 
        {
            // TODO: Test what happens if I disable a key - can I still verify with it?
            try 
            {
                // Create a *digest* that we can then sign
                var digest = GetSHA512Digest(inputText);

                // This will use the latest key version
                // Note that the type of digest (SHA512 here) determines which type of signature algo to use!
                var signatureResult = await keyVaultClient.SignAsync($"{keyVaultUrl}keys/{keyName}",JsonWebKeySignatureAlgorithm.RS512, digest);

                // In the real world, we'd combine these with the data and potentially store all of it together
                var signingKey = signatureResult.Kid;
                var signature = signatureResult.Result;  
                var signingAlgorithm = JsonWebKeySignatureAlgorithm.RS512;

                // Now to verify the text
                var newDigest = GetSHA512Digest(inputText + "a");
                var verifyResult = await keyVaultClient.VerifyAsync(signingKey, signingAlgorithm, newDigest, signature);
                if (!verifyResult) 
                {
                    throw new Exception("Failed to verify the data");
                }
            }
            catch (Exception e) 
            {
                throw;
            }

        }

        private static byte[] GetSHA512Digest(string input)
        {
            var sha = new SHA512Managed();
            var bytes = System.Text.Encoding.UTF8.GetBytes(input);
            return sha.ComputeHash(bytes);
        }


        private static string inputText = @"AzureServiceTokenProvider will use the developer's security context to get a token to authenticate to Key Vault. This removes the need to create a service principal, and share it with the development team. It also prevents credentials from being checked in to source code. AzureServiceTokenProvider will use Azure CLI or Active Directory Integrated Authentication to authenticate to Azure AD to get a token. That token will be used to fetch the secret from Azure Key Vault.
Azure CLI will work if the following conditions are met:
You have Azure CLI 2.0 installed. Version 2.0.12 supports the get-access-token option used by AzureServiceTokenProvider. If you have an earlier version, please upgrade.
You are logged into Azure CLI. You can login using az login command.
Azure Active Directory Authentication will only work if the following conditions are met:
Your on-premise active directory is synced with Azure AD.
You are running this code on a domain joined machine.
Since your developer account has access to the Key Vault, you should see the secret on the web page. Principal Used will show type User and your user account.
You can also use a service principal to run the application on your local development machine. See the section Running the application using a service principal later in the tutorial on how to do this.";
    }
}
