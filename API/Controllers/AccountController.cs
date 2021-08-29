using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTO;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }
        // [HttpPost("register")]
        // public async Task<ActionResult<AppUser>> register(string username,string password){

        //     using var hmac = new HMACSHA512();
        //     var user = new AppUser(){
        //         UserName = username,
        //         PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password)),
        //         PasswordSalt = hmac.Key
        //     };
        //     _context.Users.Add(user);
        //     await _context.SaveChangesAsync();
        //     return user;
        // }
        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDTO registerdto){

            if(await UserExistAsync(registerdto.Username)){
                return BadRequest("User name is taken");
            }
            using var hmac = new HMACSHA512();
            var user = new AppUser(){
                UserName = registerdto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerdto.Password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return new UserDto(){
                Username = user.UserName,
                UserToken = _tokenService.CreateToken(user)
            };
        }
        
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDTO logindto){
            var user  = await _context.Users.SingleOrDefaultAsync(x=>x.UserName==logindto.Username.ToLower());
            if(user==null){
                return Unauthorized("Incorrect Username");
            }
            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(logindto.Password));
            for(var i = 0; i < computedHash.Length; i++){
                if(computedHash[i]!=user.PasswordHash[i]){
                    return Unauthorized("username and password do not match");
                }
            }     
            
            return new UserDto(){
                Username = logindto.Username,
                UserToken = _tokenService.CreateToken(user)
            };
        }
        private async Task<bool> UserExistAsync(string username){
            return await _context.Users.AnyAsync(x=>x.UserName==username.ToLower());
        }

    }
}