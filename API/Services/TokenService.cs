using API.Entities;
using API.Interfaces;
using  System.Text;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Security.Claims;
using System;

namespace API.Services{
    public class TokenService : ITokenService
    {   
        private readonly SymmetricSecurityKey _key;

        public TokenService(IConfiguration config)
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));
        }

        public string CreateToken(AppUser user)
        {
            //Parts of a token
            // 1. Claim
            var claims  = new List<Claim>(){
                new Claim(JwtRegisteredClaimNames.NameId,user.UserName)
            };
            //2. Credentials using symmetric Key
            var creds = new SigningCredentials(_key,SecurityAlgorithms.HmacSha512Signature);
            //3. Actual token body/ token descriptor
            var tokenDescriptor = new SecurityTokenDescriptor{
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),
                SigningCredentials = creds
            };
            // token handler is used to Create token and then write it in response strea,
            var tokenHandler = new JwtSecurityTokenHandler();
            var token  = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}