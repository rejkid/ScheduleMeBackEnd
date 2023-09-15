using log4net;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Linq;
using System.Text;
using WebApi.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using WebApi.Entities;

namespace WebApi.Middleware
{
    public class WebApiActionFilter : IActionFilter
    {
        private static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        private readonly AppSettings _appSettings;
        private DataContext _context;

        public WebApiActionFilter(IOptions<AppSettings> appSettings, DataContext context)
        {
            _appSettings = appSettings.Value;
            _context = context;
        }
        public void OnActionExecuting(ActionExecutingContext context)
        {
            var token = context.HttpContext.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            if(token == null)
            {
                return;
            }

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_appSettings.Secret);

                //SecurityToken validatedToken = new SecurityToken();
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var accountId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

                var account = _context.Accounts.Include(x => x.RefreshTokens).SingleOrDefault(x => x.AccountId == accountId);
                //Account account = (Account)context.HttpContext.Items["Account"];
                log.InfoFormat("\n\n----------------------- Start processing request for  AccountId:{0} First Name:{1} Last Name:{2} e-mail:{3}  path:{4}",
                account.AccountId,
                account.FirstName,
                account.LastName,
                    account.Email,
                    context.HttpContext.Request.Path
                    );
                //}
            }
            catch (Exception error)
            {
                // do nothing if jwt validation fails
                // account is not attached to context so request won't have access to secure routes
                //var account = context.HttpContext.Items["Account"];
                Console.WriteLine("Failed:" + error);
                //log.Error("JWT (expired): for path: " + context.HttpContext.Request.Path);
            }
        }

        public void OnActionExecuted(ActionExecutedContext context)
        {
            var token = context.HttpContext.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            if (token == null)
            {
                return;
            }

            try
            {
                //if (token != null)
                //{
                //    var handler = new JwtSecurityTokenHandler();
                //    var jsonToken = handler.ReadToken(token);
                //    var tokenS = jsonToken as JwtSecurityToken;
                //    bool tokenValid = CheckTokenIsValid(token);
                //    if (!tokenValid)
                //    {
                //        // Find out the reason why it is not valid and log it
                //        var jwtSecurityToken = handler.ReadJwtToken(token);
                //        var jwtTokenTest = (JwtSecurityToken)jwtSecurityToken;
                //        var accountID = int.Parse(jwtTokenTest.Claims.First(x => x.Type == "id").Value);
                //        var accountTest = _context.Accounts.FindAsync(accountID);

                //        var tokenExpTest = jwtTokenTest.Claims.First(claim => claim.Type.Equals("exp")).Value;
                //        var ticksTest = long.Parse(tokenExpTest);
                //        var tokenDateTest = DateTimeOffset.FromUnixTimeSeconds(ticksTest).UtcDateTime;
                //        log.InfoFormat("JWT expiration(Invalid) date for {0} {1} was {2}", accountTest.FirstName, accountTest.LastName, tokenDateTest.ToLocalTime().ToString());
                //        var accountIdTest = int.Parse(jwtTokenTest.Claims.Where(x => x.Type == "id").FirstOrDefault().Value); //int.Parse();
                //        var securityToken = handler.ReadToken(token) as JwtSecurityToken;
                //        var stringClaimValue = securityToken.Claims.First(claim => claim.Type == "id").Value;
                //    }

                    var tokenHandler = new JwtSecurityTokenHandler();
                    var key = Encoding.ASCII.GetBytes(_appSettings.Secret);

                    //SecurityToken validatedToken = new SecurityToken();
                    tokenHandler.ValidateToken(token, new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                        ClockSkew = TimeSpan.Zero
                    }, out SecurityToken validatedToken);

                    var jwtToken = (JwtSecurityToken)validatedToken;
                    var accountId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

                    var account = _context.Accounts.Include(x => x.RefreshTokens).SingleOrDefault(x => x.AccountId == accountId);
                    log.InfoFormat("\n----------------------- Finish processing request for  AccountId:{0} First Name:{1} Last Name:{2} e-mail:{3} path:{4}\n\n",
                        account.AccountId,
                        account.FirstName,
                        account.LastName,
                        account.Email,
                        context.HttpContext.Request.Path
                        );
                //}
            }
            catch (Exception error)
            {
                // do nothing if jwt validation fails
                // account is not attached to context so request won't have access to secure routes
                //var account = context.HttpContext.Items["Account"];
                //Console.WriteLine("Failed:" + error);
                //log.Info("JWT (expired): for path: " + context.HttpContext.Request.Path);
            }
        }

        public static bool CheckTokenIsValid(string token)
        {
            var tokenTicks = GetTokenExpirationTime(token);
            var tokenDate = DateTimeOffset.FromUnixTimeSeconds(tokenTicks).UtcDateTime;

            var now = DateTime.Now.ToUniversalTime();

            var valid = tokenDate >= now;
            log.Info("JWT expiration date - local time: " + tokenDate.ToLocalTime() + " Now: " + now.ToLocalTime());
            if (!valid)
            {
                log.Info("JWT expiration date (expired): " + tokenDate.ToLocalTime() + " Now: " + now.ToLocalTime());
            }
            return valid;
        }
        public static long GetTokenExpirationTime(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);
            var tokenExp = jwtSecurityToken.Claims.First(claim => claim.Type.Equals("exp")).Value;
            var ticks = long.Parse(tokenExp);
            return ticks;
        }
    }
}
