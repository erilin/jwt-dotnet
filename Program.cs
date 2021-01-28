using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace net_jwt
{
    class Program
    {
        static void Main(string[] args)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("13374967ym3v0987y36y");
            var expires = DateTime.UtcNow.AddMinutes(30);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                            {
                              new Claim(ClaimTypes.Name, "Erik"),
                              new Claim(ClaimTypes.Sid, Convert.ToString(1337)),
                            }),
                Expires = expires,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            System.Console.WriteLine(tokenHandler.WriteToken(token));
        }
    }

    public class SigningKeyHelper
    {
        public static SecurityKey BuildRsaSigningKey(string credentialsPath)
        {
            var json = System.IO.File.ReadAllText($@"{credentialsPath}");
            var obj = JsonConvert.DeserializeObject<SigningKey>(json);

            var rsaParams = new RSAParameters();
            rsaParams.D = Convert.FromBase64String(obj.Parameters.D);
            rsaParams.DP = Convert.FromBase64String(obj.Parameters.DP);
            rsaParams.DQ = Convert.FromBase64String(obj.Parameters.DQ);
            rsaParams.Exponent = Convert.FromBase64String(obj.Parameters.Exponent);
            rsaParams.InverseQ = Convert.FromBase64String(obj.Parameters.InverseQ);
            rsaParams.Modulus = Convert.FromBase64String(obj.Parameters.Modulus);
            rsaParams.P = Convert.FromBase64String(obj.Parameters.P);
            rsaParams.Q = Convert.FromBase64String(obj.Parameters.Q);
            var key = new RsaSecurityKey(rsaParams);
            key.KeyId = obj.KeyId;
            return key;
        }

        class SigningKey
        {
            public string KeyId { get; set; }
            public SigningKeyParameters Parameters { get; set; }
        }

        class SigningKeyParameters
        {
            public string D { get; set; }
            public string DP { get; set; }
            public string DQ { get; set; }
            public string Exponent { get; set; }
            public string InverseQ { get; set; }
            public string Modulus { get; set; }
            public string P { get; set; }
            public string Q { get; set; }
        }
    }
}
