using System;
using System.Security.Cryptography;
using HashComparer.HashHelpers;
using Xunit;

namespace HashComparer.Tests
{
    public class Pbdkdf2Tests
    {
        [Fact]
        public void VerifyHashedPasswordV2_Should_Hash_Password_Correctly()
        {
            //arrange
            string password = "_s3c43T";
            var generator = RandomNumberGenerator.Create();
            byte[] hashedPassword = Pbkdf2.HashPasswordV2(password, generator);

            string hashedPasswordString = Convert.ToBase64String(hashedPassword);

            //act
            bool isValid = Pbkdf2.VerifyHashedPasswordV2(hashedPassword, password);

            //assert
            Assert.True(isValid);
        }

        [Theory]
        [InlineData("PasswordUltraSecret", @"ACM0FwABwv9ssih6Fbtc5Ppj0SdYcCp/kzvYfEn4ast6cP7BQcyAOrw3jZ7VhfVhwg==")]
        [InlineData("_s3c43T", @"APaA8RDUJFFLkyR549eWIZHLP+wU9MvrmxJF62amktJXT6wNEdYkyr4OQXa1kFWJ0w==")]
        public void VerifyHashedPasswordV2_Valid_Hashed_Passwords_Should_Return_True(string password, string hash)
        {
            //arrange
            byte[] hashtBytes = Convert.FromBase64String(hash);

            //act
            bool isValid = Pbkdf2.VerifyHashedPasswordV2(hashtBytes, password);

            //assert
            Assert.True(isValid);
        }

        [Theory]
        [InlineData("PasswordUltraSecretINVALIDO", @"ACM0FwABwv9ssih6Fbtc5Ppj0SdYcCp/kzvYfEn4ast6cP7BQcyAOrw3jZ7VhfVhwg==")]
        [InlineData("_s3c43TINVALIDO", @"APaA8RDUJFFLkyR549eWIZHLP +wU9MvrmxJF62amktJXT6wNEdYkyr4OQXa1kFWJ0w==")]
        public void VerifyHashedPasswordV2_Invalid_Hashed_Passwords_Should_Return_False(string password, string hash)
        {
            //arrange
            byte[] hashtBytes = Convert.FromBase64String(hash);

            //act
            bool isValid = Pbkdf2.VerifyHashedPasswordV2(hashtBytes, password);

            //assert
            Assert.False(isValid);
        }
    }
}
