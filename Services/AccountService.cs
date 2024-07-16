using AutoMapper;
using BC = BCrypt.Net.BCrypt;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApi.Entities;
using WebApi.Helpers;
using WebApi.Models.Accounts;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Microsoft.AspNetCore.WebUtilities;
using System.Diagnostics;
using System.Threading;
using log4net;
using Microsoft.EntityFrameworkCore.Storage;
using System.Security.Policy;
using Microsoft.AspNetCore.SignalR;
using WebApi.Hub;
using System.Runtime.Serialization;
using System.Security.Principal;
using Microsoft.AspNetCore.Mvc;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using Google.Apis.Drive.v3.Data;
using User = WebApi.Entities.User;
using Aspose.Cells;
using System.Linq.Expressions;
using static Google.Apis.Requests.BatchRequest;
using System.Data;
using static log4net.Appender.RollingFileAppender;
using Org.BouncyCastle.Ocsp;
using Aspose.Cells.Timelines;
using System.Collections;
using System.Xml;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Globalization;
using Microsoft.Extensions.Primitives;
using Microsoft.AspNetCore.Components.Forms;
using System.Runtime.InteropServices;
using CliWrap;
using Aspose.Cells.Drawing;
using System.Net.Mail;
using static System.Net.Mime.MediaTypeNames;
using Microsoft.CodeAnalysis.Elfie.Diagnostics;
using iText.Kernel.Pdf;
using iText.Layout.Element;
using iText.Layout.Properties;
using iText.Layout;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Table = iText.Layout.Element.Table;
using iText.Kernel.Colors;
using iText.IO.Font;
using iText.Kernel.Font;
using Text = iText.Layout.Element.Text;
using iText.Kernel.Geom;
using Swashbuckle.AspNetCore.SwaggerGen;
using static iText.Svg.SvgConstants;
using System.Diagnostics.Metrics;
using Aspose.Pdf.Structure;
using iText.Commons.Actions.Contexts;

namespace WebApi.Services
{
    public interface IAccountService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
        AuthenticateResponse RefreshToken(string token, string ipAddress);
        void RevokeToken(string token, string ipAddress);
        IdentityResult Register(RegisterRequest model, string origin);
        void VerifyEmail(VerifyEmailRequest model);
        void ForgotPassword(ForgotPasswordRequest model, string origin);
        void ValidateResetToken(ValidateResetTokenRequest mode);
        void ResetPassword(ResetPasswordRequest model);
        IEnumerable<AccountResponse> GetAll();
        IEnumerable<AccountResponse> GetAccountsForDateAndTask(AccountsByDateAndTaskDTO accountsByDateAndTaskDTO);

        AccountResponse GetById(string id);

        public ScheduleDateTimeResponse GetAllDates();
        public DateFunctionTeamResponse GetTeamsByFunctionForDate(string date);

        AccountResponse Create(CreateRequest model);
        AccountResponse Update(string id, AccountRequest model);
        public AccountResponse DeleteSchedule(string id, UpdateScheduleRequest scheduleReq);
        void DeleteSchedules4Date(string dateStr);

        public IEnumerable<UpdateScheduleRequest> DeleteAllSchedules();
        public Boolean DeleteAllTimeSlots();

        public AccountResponse AddSchedule(string id, UpdateScheduleRequest scheduleReq);
        public AccountResponse UpdateSchedule(string id, UpdateScheduleRequest scheduleReq);
        public IEnumerable<AccountResponse> GetSchedules4Date(string dateStr);
        public (AccountResponse, string) DeleteFunction(string id, AgentTask functionReq);
        public AccountResponse AddFunction(string id, AgentTask functionReq);
        //public SchedulePoolElementsResponse ChangeUserAvailability(int id, UpdateScheduleRequest scheduleReq);
        public AccountResponse GetScheduleFromPool(string id, UpdateScheduleRequest scheduleReq);
        public AccountResponse MoveSchedule2Pool(string id, UpdateScheduleRequest scheduleReq);

        public SchedulePoolElementsResponse GetAvailablePoolElementsForAccount(string id);
        public SchedulePoolElementsResponse GetAllAvailablePoolElements();

        public SchedulePoolElement RemoveFromPool(int id, string email, string userFunction);

        void Delete(string id);

        public List<AgentTaskConfig> GetAllAgentTaskConfigs();

        public AgentTaskConfig[] UpdateAgentTaskConfig(string id, UpdateAgentTaskConfigRequest agentTaskConfigReq);

        public void DeleteAgentTaskConfig(string id);

        public void DeleteAllAgentTaskConfigs();

        public void UploadUserAccounts(string path);
        Boolean GenerateSchedules();
        public void ImportTimeSlotsTasks(string xlsmfullPath);

        public Byte[] DownloadSchedules();

        public TimeSlotTasks[] GetTimeSlotsTasks();

        public TimeSlotTasks[] SetTimeSlotsTasks(TimeSlotTasks tasks);
        public Boolean DeleteTimeSlotsTasks(TimeSlotTasks slotFromClient);

        public IEnumerable<AccountResponse> DeleteAllUserAccounts();
        public bool GetAutoEmail();
        public bool SetAutoEmail(bool autoEmail);
        public void SendRemindingEmail4Functions();
    }

    public class AccountService : IAccountService
    {
        private const string AGENTS_2_TASKS_FORMAT = "yyyyMMddHHmm";// "dd/MMM/yyyy/h:mm";
        private const string SEPARATOR = "&";
        private const string A2T_INPUT = "a2t.txt";
        private const string A2T_OUTPUT = "a2t_result.txt";
        private const string A2T_EXE = "Agents2Tasks.exe";
        private const string CLEANER = "Cleaner";
        public static TimeSpan THREE_DAYS_TIMEOUT = new TimeSpan(3, 0, 0, 0);   // Three days time span
        public static TimeSpan WEEK_TIMEOUT = new TimeSpan(7, 0, 0, 0);         // Week time span

        private static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        private readonly DataContext _context;
        private readonly IMapper _mapper;
        private readonly AppSettings _appSettings;
        private readonly IEmailService _emailService;
        public static readonly SemaphoreSlim semaphoreObject = new SemaphoreSlim(1, 1);
        private readonly IHubContext<MessageHub, IMessageHubClient> _hubContext;
        private IConfiguration _configuration;
        private readonly IUserStore<Account> _userStore;
        private readonly IUserEmailStore<Account> _emailStore;
        private readonly UserManager<Account> _userManager;
        private Microsoft.AspNetCore.Hosting.IWebHostEnvironment _hostingEnvironment;

        public AccountService(
            DataContext context,
            IMapper mapper,
            IOptions<AppSettings> appSettings,
            IEmailService emailService,
            IHubContext<MessageHub, IMessageHubClient> hubContext,
            UserManager<Account> userManager,
            IConfiguration configuration,
            IUserStore<Account> userStore,
            Microsoft.AspNetCore.Hosting.IWebHostEnvironment hostingEnvironment
            )
        {
            _context = context;
            _mapper = mapper;
            _appSettings = appSettings.Value;
            _emailService = emailService;
            _hubContext = hubContext;
            _configuration = configuration;

            _userManager = userManager;
            _userStore = userStore;
            _emailStore = (IUserEmailStore<Account>)_userStore;
            _hostingEnvironment = hostingEnvironment;
        }

        public static int CompareScheduleDateTime(ScheduleDateTime x, ScheduleDateTime y)
        {
            if (x == null)
                return -1;
            if (y == null)
                return 1;
            var date1 = DateTime.ParseExact(x.Date, ConstantsDefined.DateTimeFormat, CultureInfo.InvariantCulture);
            var date2 = DateTime.ParseExact(y.Date, ConstantsDefined.DateTimeFormat, CultureInfo.InvariantCulture);

            return date1.CompareTo(date2);
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
        {
            log.Info("Authenticate before locking");
            semaphoreObject.Wait();
            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = _context.Accounts.Include(x => x.RefreshTokens).SingleOrDefault(x => x.Email == model.Email && x.DOB == model.Dob);

                    if (account == null || !account.IsVerified || !BC.Verify(model.Password, account.PasswordHash))
                        throw new AppException("Email, DOB or password is incorrect");

                    // authentication successful so generate jwt and refresh tokens
                    var jwtToken = generateJwtToken(account);

                    var refreshToken = generateRefreshToken(ipAddress);
                    account.RefreshTokens.Add(refreshToken);

                    // remove old refresh tokens from account
                    removeOldRefreshTokens(account);

                    // save changes to db
                    _context.Update(account);
                    _context.SaveChanges();

                    var response = _mapper.Map<AuthenticateResponse>(account);
                    response.JwtToken = jwtToken;
                    response.RefreshToken = refreshToken.Token;

                    transaction.Commit();
                    return response;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in Authenticate:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("Authenticate after locking");
                }
            }
        }

        public AuthenticateResponse RefreshToken(string token, string ipAddress)
        {
            log.Info("RefreshToken before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var (refreshToken, account) = getRefreshToken(token);

                    log.InfoFormat("Old RefreshToken= {0} for {1} {2}",
                        refreshToken.Token,
                        account.FirstName,
                        account.LastName);

                    // replace old refresh token with a new one and save
                    var newRefreshToken = generateRefreshToken(ipAddress);
                    refreshToken.Revoked = DateTime.UtcNow;
                    refreshToken.RevokedByIp = ipAddress;
                    refreshToken.ReplacedByToken = newRefreshToken.Token;
                    account.RefreshTokens.Add(newRefreshToken);

                    removeOldRefreshTokens(account);

                    log.InfoFormat("New RefreshToken= {0} for {1} {2}",
                        newRefreshToken.Token,
                        account.FirstName,
                        account.LastName);

                    _context.Update(account);
                    _context.SaveChanges();

                    // generate new jwt
                    var jwtToken = generateJwtToken(account);

                    var response = _mapper.Map<AuthenticateResponse>(account);
                    response.JwtToken = jwtToken;
                    response.RefreshToken = newRefreshToken.Token;

                    transaction.Commit();
                    return response;
                }
                catch 
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in RefreshToken:");
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("RefreshToken after locking");
                }
            }
        }

        public void RevokeToken(string token, string ipAddress)
        {
            log.Info("RevokeToken before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var (refreshToken, account) = getRefreshToken(token);

                    // revoke token and save
                    refreshToken.Revoked = DateTime.UtcNow;
                    refreshToken.RevokedByIp = ipAddress;
                    _context.Update(account);
                    _context.SaveChanges();
                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in RevokeToken:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("RevokeToken after locking");
                }
            }
        }

        public IdentityResult Register(RegisterRequest model, string origin)
        {
            log.Info("Register before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    // validate
                    Account user = _context.Accounts.Include(x => x.RefreshTokens).SingleOrDefault(x => x.Email == model.Email && x.DOB == model.Dob);
                    if (user != null)
                    {
                        // send already registered error in email to prevent account enumeration
                        sendAlreadyRegisteredEmail(model.Email, model.Dob, origin);
                        //var claims = new List<Claim>();
                        //claims.Add(new Claim("DOB", account.DOB));
                        //claims.Add(new Claim(ClaimTypes.Email, account.Email));
                        //var id = new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie);
                        //var principal = new ClaimsPrincipal(new ClaimsIdentity(null, "Basic"));
                        //var result = await _userManager.GetUserAsync(user, model.Password);
                        transaction.Commit();
                        return IdentityResult.Success;
                    }

                    
                    //var user1 = Activator.CreateInstance<Account>();
                
                    // map model to new account object
                    user = _mapper.Map<Account>(model);

                    //await _userStore.SetUserNameAsync(user, model.Email.Split('@')[0], CancellationToken.None);
                    //await _emailStore.SetEmailAsync(user, model.Email, CancellationToken.None);

                    var isFirstAccount = _context.Accounts.Count() == 0;
                    user.Role = isFirstAccount ? Role.Admin : Role.User;
                    user.Created = DateTime.UtcNow;
                    user.VerificationToken = randomTokenString();

                    // hash password
                    user.PasswordHash = BC.HashPassword(model.Password,12);

                    var result = _userManager.CreateAsync(user).GetAwaiter().GetResult();
                    Debug.Assert(result != null && IdentityResult.Success.Succeeded == result.Succeeded);
                    if (result.Succeeded)
                    {
                        // send email
                        sendVerificationEmail(user, origin);
                    }
                    transaction.Commit();
                    log.WarnFormat("Registration successful for = '{0}' ", model.Email);
                    return result;
                 

                    /*
                    // map model to new account object
                    var account = _mapper.Map<Account>(model);

                    // first registered account is an admin
                    var isFirstAccount = _context.Accounts.Count() == 0;
                    account.Role = isFirstAccount ? Role.Admin : Role.User;
                    account.Created = DateTime.UtcNow;
                    account.VerificationToken = randomTokenString();

                    // hash password
                    account.PasswordHash = BC.HashPassword(model.Password);

                    // save account
                    _context.Accounts.Add(account);
                    _context.SaveChanges();

                    // send email
                    sendVerificationEmail(account, origin);
                    

                    transaction.Commit();
                    log.WarnFormat("Registration successful for = {0} ", model.Email);
                    return IdentityResult.Success;
                    */
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in Register:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("Register after locking");
                }
            }
        }

        public AccountResponse Create(CreateRequest model)
        {
            log.Info("Create before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    // validate
                    if (_context.Accounts.Any(x => x.Email == model.Email && x.DOB == model.Dob))
                        throw new AppException($"User with Email '{model.Email}' DOB: '{model.Dob}' is already registered");

                    // map model to new account object
                    var account = _mapper.Map<Account>(model);
                    account.Created = DateTime.UtcNow;
                    account.Verified = DateTime.UtcNow;

                    // hash password
                    account.PasswordHash = BC.HashPassword(model.Password);

                    // save account
                    //_context.Accounts.Add(account);
                    //_context.SaveChanges();
                    var result = _userManager.CreateAsync(account).GetAwaiter().GetResult();
                    Debug.Assert(result != null && IdentityResult.Success.Succeeded == result.Succeeded);

                    AccountResponse response = _mapper.Map<AccountResponse>(account);
                    transaction.Commit();

                    return response;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in Create:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("Create after locking");
                }
            }
        }

        public AccountResponse Update(string id, AccountRequest model)
        {
            log.Info("Update before locking"); ;
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = getAccount(id);
                    // validate
                    if (account.Email != model.Email && _context.Accounts.Any(x => x.Email == model.Email && x.DOB == model.Dob))
                        throw new AppException($"Email '{model.Email}' is already taken");

                    // hash password if it was entered
                    if (!string.IsNullOrEmpty(model.Password))
                        account.PasswordHash = BC.HashPassword(model.Password);

                    _mapper.Map(model, account);

                    account.Updated = DateTime.UtcNow;
                    //_context.Accounts.Update(account);
                    //_context.SaveChanges();
                    var result = _userManager.UpdateAsync(account).GetAwaiter().GetResult();
                    Debug.Assert(result != null && IdentityResult.Success.Succeeded == result.Succeeded);

                    AccountResponse response = _mapper.Map<AccountResponse>(account);

                    transaction.Commit();
                    return response;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in Update:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("Update after locking"); ;
                }
            }
        }

        public void VerifyEmail(VerifyEmailRequest model)
        {
            log.Info("VerifyEmail before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = _context.Accounts.SingleOrDefault(x => x.VerificationToken == model.Token && x.DOB == model.Dob);

                    if (account == null) throw new AppException("Verification failed");

                    account.Verified = DateTime.UtcNow;
                    account.VerificationToken = null;

                    _context.Accounts.Update(account);
                    _context.SaveChanges();
                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name);
                    log.Error(Thread.CurrentThread.Name + "Error occurred in VerifyEmail:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("VerifyEmail after locking");
                }
            }
        }

        public void ForgotPassword(ForgotPasswordRequest model, string origin)
        {
            log.Info("ForgotPassword before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = _context.Accounts.SingleOrDefault(x => x.Email == model.Email && x.DOB == model.Dob);

                    // always return ok response to prevent email enumeration
                    if (account == null)
                    {
                        throw new AppException("Email or DOB is incorrect");
                    }

                    // create reset token that expires after 1 day
                    account.ResetToken = randomTokenString();
                    account.ResetTokenExpires = DateTime.UtcNow.AddDays(1);

                    _context.Accounts.Update(account);
                    _context.SaveChanges();

                    // send email
                    sendPasswordResetEmail(account, origin);

                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in ForgotPassword:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("ForgotPassword after locking");
                }
            }
        }

        public void ValidateResetToken(ValidateResetTokenRequest model)
        {
            log.Info("ValidateResetToken before locking");
            semaphoreObject.Wait();
            try
            {
                var account = _context.Accounts.SingleOrDefault(x => x.ResetToken == model.Token && x.DOB == model.Dob && x.ResetTokenExpires > DateTime.UtcNow);

                if (account == null)
                    throw new AppException("Invalid token");
            }
            catch (Exception ex)
            {
                Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                log.Error(Thread.CurrentThread.Name + "Error occurred in ValidateResetToken:", ex);
                throw;
            }
            finally
            {
                semaphoreObject.Release();
                log.Info("ValidateResetToken after locking");
            }
        }

        public void ResetPassword(ResetPasswordRequest model)
        {
            log.Info("ResetPassword before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = _context.Accounts.SingleOrDefault(x =>
                        x.ResetToken == model.Token &&
                        x.ResetTokenExpires > DateTime.UtcNow);

                    if (account == null)
                        throw new AppException("Invalid token");

                    // update password and remove reset token
                    account.PasswordHash = BC.HashPassword(model.Password);
                    account.PasswordReset = DateTime.UtcNow;
                    account.ResetToken = null;
                    account.ResetTokenExpires = null;

                    _context.Accounts.Update(account);
                    _context.SaveChanges();

                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in ResetPassword:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("ResetPassword after locking");
                }
            }
        }

        public IEnumerable<AccountResponse> GetAll()
        {
            log.Info("GetAll before locking");
            semaphoreObject.Wait();

            try
            {
                var accounts = _context.Accounts.Include(x => x.UserFunctions).Include(x => x.Schedules).OrderBy(a => a.Created).ToList();
                return _mapper.Map<IList<AccountResponse>>(accounts);
            }
            catch (Exception ex)
            {
                Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                log.Error(Thread.CurrentThread.Name + "Error occurred in GetAll:", ex);
                throw;
            }
            finally
            {
                semaphoreObject.Release();
                log.Info("GetAll after locking");
            }
        }

        public IEnumerable<AccountResponse> GetAccountsForDateAndTask(AccountsByDateAndTaskDTO accountsByDateAndTaskDTO)
        {
            log.Info("GetAccountsForDate before locking");
            semaphoreObject.Wait();

            try
            {
                var accounts = _context.Accounts
                  .Include(x => x.UserFunctions).Include(x => x.Schedules)
                  .Where(account => account.Schedules
                    .Any(s => s.Date.Equals(accountsByDateAndTaskDTO.DateStr) && s.UserFunction.Equals(accountsByDateAndTaskDTO.Task)))
                  .ToArray();

                return _mapper.Map<IList<AccountResponse>>(accounts);
            }
            catch (Exception ex)
            {
                Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                log.Error(Thread.CurrentThread.Name + "Error occurred in GetAccountsForDate:", ex);
                throw;
            }
            finally
            {
                semaphoreObject.Release();
                log.Info("GetAccountsForDate after locking");
            }
        }

        public ScheduleDateTimeResponse GetAllDates()
        {
            log.Info("GetAllDates before locking");
            semaphoreObject.Wait();
            try
            {
                return GetAllDatesWithoutLock();
            }
            catch (Exception ex)
            {
                Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                log.Error(Thread.CurrentThread.Name + "Error occurred in GetAllDates:", ex);
                throw;
            }
            finally
            {
                semaphoreObject.Release();
                log.Info("GetAllDates after locking");
            }
        }

        private ScheduleDateTimeResponse GetAllDatesWithoutLock()
        {
            ScheduleDateTimeResponse response = new ScheduleDateTimeResponse();
            response.ScheduleDateTimes = new List<ScheduleDateTime>();

            var accounts = _context.Accounts;
            var accountAll = _context.Accounts.Include(x => x.Schedules).ToList();
            foreach (var item in accountAll)
            {
                foreach (var schedule in item.Schedules)
                {
                    Boolean found = false;
                    foreach (var dt in response.ScheduleDateTimes)
                    {
                        if (dt.Date == schedule.Date)
                        {
                            found = true; // DateTime already exists - break the for loop
                            break;
                        }
                    }
                    if (!found)
                    {
                        ScheduleDateTime sdt = new ScheduleDateTime();
                        sdt.Date = schedule.Date;
                        sdt.Id = schedule.ScheduleId;
                        response.ScheduleDateTimes.Add(sdt);
                    }
                }
            }
            return response;
        }

        public DateFunctionTeamResponse GetTeamsByFunctionForDate(string dateStr)
        {
            log.Info("GetTeamsByFunctionForDate before locking");
            semaphoreObject.Wait();

            try
            {
                return GetTeamsByFunctionForDateWithoutLock(dateStr);
            }
            catch (Exception ex)
            {
                Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                log.Error(Thread.CurrentThread.Name + "Error occurred in GetTeamsByFunctionForDate:", ex);
                throw;
            }
            finally
            {
                semaphoreObject.Release();
                log.Info("GetTeamsByFunctionForDate after locking");
            }
        }

        private DateFunctionTeamResponse GetTeamsByFunctionForDateWithoutLock(string dateStr)
        {
            var accountAll = _context.Accounts.Include(x => x.Schedules).ToList();
            var dateTime = dateStr;

            var offset = TimeZoneInfo.Local.GetUtcOffset(DateTime.UtcNow);

            log.InfoFormat("Date requested string {0} parsed value {1} offset {2}",
                            dateStr,
                            dateTime,
                            offset);

            DateFunctionTeamResponse response = new DateFunctionTeamResponse();
            response.DateFunctionTeams = new List<DateFunctionTeam>();

            foreach (var account in accountAll)
            {
                foreach (var schedule in account.Schedules)
                {
                    DateFunctionTeam team = null;

                    if (schedule.Date == dateTime)
                    {
                        // Find existing team for the date and function
                        foreach (var item in response.DateFunctionTeams)
                        {
                            if (schedule.Date == item.Date && item.UserFunction == schedule.UserFunction)
                            {
                                team = item;
                                break;
                            }
                        }
                        if (team == null)
                        {
                            team = new DateFunctionTeam(dateTime, schedule.UserFunction);
                            response.DateFunctionTeams.Add(team);
                        }

                        User user = _mapper.Map<User>(account);
                        user.Function = schedule.UserFunction;
                        user.UserAvailability = schedule.UserAvailability;
                        user.ScheduleGroup = schedule.ScheduleGroup;
                        team.Users.Add(user);
                    }
                }
            }
            return response;
        }

        public AccountResponse GetById(string id)
        {
            log.Info("GetById before locking");
            semaphoreObject.Wait();

            try
            {
                var account = getAccount(id);

                AccountResponse retVal = _mapper.Map<AccountResponse>(account);

                return retVal;
            }
            catch (Exception ex)
            {
                Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                log.Error(Thread.CurrentThread.Name + "Error occurred in GetById:", ex);
                throw;
            }
            finally
            {
                semaphoreObject.Release();
                log.Info("GetById after locking");
            }
        }

        public AccountResponse DeleteSchedule(string id, UpdateScheduleRequest scheduleReq)
        {
            log.InfoFormat("DeleteSchedule before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = getAccount(id);

                    Schedule toRemove = null;

                    foreach (var item in account.Schedules)
                    {
                        string dateTime = scheduleReq.Date;
                        if ((item.Date == dateTime) && item.UserFunction == scheduleReq.UserFunction)
                        {
                            toRemove = item;
                            break; // Found
                        }
                    }
                    if (toRemove != null)
                    {
                        _context.Schedules.RemoveRange(toRemove);
                    }
                    else
                    {
                        log.Info("DeleteSchedule got NULL from Schedules");
                        throw new AppException("The schedule has been already deleted");
                    }

                    account.Updated = DateTime.UtcNow;
                    _context.SaveChanges();
                    _hubContext.Clients.All.SendUpdate(id);

                    AccountResponse response = _mapper.Map<AccountResponse>(account);

                    transaction.Commit();

                    return response;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.", ex);
                    log.Error(Thread.CurrentThread.Name + "Error occurred in DeleteSchedule:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    Console.WriteLine("DeleteSchedule after locking");
                }
            }
        }
        public void DeleteSchedules4Date(string dateStr)
        {
            log.InfoFormat("DeleteSchedules4Date before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var schedules = _context.Accounts.Include(x => x.Schedules).Include(x => x.UserFunctions).
                        Select(account => account.Schedules).SelectMany(s => s.Where(s=> s.Date.Equals(dateStr))).ToArray();
                    _context.Schedules.RemoveRange(schedules);

                    _context.SaveChanges();
                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.", ex);
                    log.Error(Thread.CurrentThread.Name + "Error occurred in DeleteSchedules4Date:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    Console.WriteLine("DeleteSchedules4Date after locking");
                }
            }
        }
        public IEnumerable<UpdateScheduleRequest> DeleteAllSchedules()
        {
            log.Info("DeleteAllSchedules before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var foundSchedules = _context.Schedules.ToArray().ToList();
                    _context.Schedules.RemoveRange(foundSchedules);

                    _context.SaveChanges();
                    transaction.Commit();

                    var schedules = _context.Schedules;
                    return _mapper.Map<IList<UpdateScheduleRequest>>(schedules);
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in DeleteAllSchedules:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("DeleteAllSchedules after locking");
                }
            }
        }

        public Boolean DeleteAllTimeSlots()
        {
            log.Info("DeleteAllTimeSlots before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var foundSchedules = _context.Schedules.ToArray().ToList();
                    _context.TimeSlotsTasks.RemoveRange(_context.TimeSlotsTasks.ToArray().ToList());

                    _context.SaveChanges();
                    transaction.Commit();
                    return true;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in DeleteAllTimeSlots:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("DeleteAllTimeSlots after locking");
                }
            }
        }

        public AccountResponse AddSchedule(string id, UpdateScheduleRequest scheduleReq)
        {
            log.Info("AddSchedule before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = getAccount(id);
                    var newSchedule = new Schedule();
                    newSchedule = _mapper.Map<Schedule>(scheduleReq);
                    var collection = account.Schedules.FindAll(s => s.Date == scheduleReq.Date 
                                    && s.UserFunction == scheduleReq.UserFunction
                                    && s.ScheduleGroup == scheduleReq.ScheduleGroup);
                    if(collection.Count > 0)
                    {
                        throw new AppException(String.Format("Schedule for {0} {1} {2} is already defined for this account", 
                            "Date: "+scheduleReq.Date,
                            "Task: " + scheduleReq.UserFunction,
                            (scheduleReq.ScheduleGroup.IsNullOrEmpty() ? "" : "Group: " + scheduleReq.ScheduleGroup)));
                    }
                    account.Schedules.Add(newSchedule);
                    _context.Accounts.Update(account);
                    _context.SaveChanges();
                    _hubContext.Clients.All.SendUpdate(id);

                    AccountResponse response = _mapper.Map<AccountResponse>(account);

                    transaction.Commit();

                    return response;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in AddSchedule:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("AddSchedule after locking");
                }
            }
        }

        public AccountResponse UpdateSchedule(string id, UpdateScheduleRequest scheduleReq)
        {
            log.Info("UpdateSchedule before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = getAccount(id);

                    foreach (var schedule in account.Schedules)
                    {
                        if (schedule.Date.CompareTo(scheduleReq.Date) == 0 && schedule.UserFunction == scheduleReq.UserFunction)
                        {
                            string dateTime = scheduleReq.NewDate;
                            schedule.Date = dateTime;
                            schedule.UserFunction = scheduleReq.NewUserFunction;

                            // Reset notification flags
                            schedule.NotifiedWeekBefore = false;
                            schedule.NotifiedThreeDaysBefore = false;
                            break;
                        }
                    }
                    _context.Accounts.Update(account);
                    _context.SaveChanges();
                    _hubContext.Clients.All.SendUpdate(id);

                    AccountResponse response = _mapper.Map<AccountResponse>(account);

                    transaction.Commit();

                    return response;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in UpdateSchedule:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("UpdateSchedule after locking");
                }
            }
        }
        public IEnumerable<AccountResponse> GetSchedules4Date(string dateStr)
        {
            log.Info("GetSchedules4Date before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var accounts = _context.Accounts.Include(x => x.Schedules).Include(x => x.UserFunctions).
                        Where(account => account.Schedules.Any(s => s.Date.Equals(dateStr))).ToArray();
                    AccountResponse[] response = _mapper.Map<AccountResponse[]>(accounts);
                    return response;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in GetSchedules4Date:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("GetSchedules4Date after locking");
                }
            }
        }

        public (AccountResponse, string) DeleteFunction(string id, AgentTask task)
        {
            log.Info("DeleteFunction before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = getAccount(id);

                    var schedules = account.Schedules
                                      .Where(s => s.UserFunction.Equals(task.UserFunction))
                                      .ToArray();

                    if (schedules.Length != 0) {
                        return (null, String.Format("Function is still being used by {0} schedule(s). Remove schedule(s) first", schedules.Length));
                        //throw new AppException(String.Format("Function is still being used by {0} schedule(s). Remove schedule(s) first", schedules.Length));
                    }

                    AgentTask toRemove = null;
                    // Purge all functions & UserFunctions  - we don't know which were changed
                    foreach (var item in account.UserFunctions)
                    {
                        if (item.UserFunction == task.UserFunction)
                        {
                            toRemove = item;
                            break; // Found
                        }
                    }
                    if (toRemove != null)
                    {
                        _context.UserFunctions.RemoveRange(toRemove);
                    }

                    account.Updated = DateTime.UtcNow;
                    _context.SaveChanges();
                    transaction.Commit();

                    return (_mapper.Map<AccountResponse>(account), "");
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in DeleteFunction:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("DeleteFunction after locking"); ;
                }
            }
        }

        public AccountResponse AddFunction(string id, AgentTask task)
        {
            log.Info("AddFunction before locking");
            semaphoreObject.Wait();
            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = getAccount(id);
                    var newFunction = new AgentTask();
                    newFunction = _mapper.Map<AgentTask>(task);
                    account.UserFunctions.Add(newFunction);
                    _context.Accounts.Update(account);
                    _context.SaveChanges();
                    transaction.Commit();

                    return _mapper.Map<AccountResponse>(account);
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in AddFunction:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("AddFunction after locking");
                }
            }
        }

        /*
        User functions
        */
        public AccountResponse MoveSchedule2Pool(string id, UpdateScheduleRequest scheduleReq)
        {
            var autoEmail = GetAutoEmail();

            log.Info("MoveSchedule2Pool before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = getAccount(id);
                    log.InfoFormat("MoveSchedule2Pool before locking for {0}. Date {1} function {2}",
                        account.FirstName, scheduleReq.Date, scheduleReq.UserFunction);

                    Schedule toRemove = null;

                    foreach (var item in account.Schedules)
                    {
                        string dateTime = scheduleReq.Date;
                        if ((item.Date == dateTime) && item.UserFunction == scheduleReq.UserFunction)
                        {
                            toRemove = item;
                            break; // Found
                        }
                    }
                    if (toRemove != null)
                    {
                        log.Info("MoveSchedule2Pool putting: " + scheduleReq.Date + "/" + scheduleReq.UserFunction + " to pool");
                        PushToPool(account, scheduleReq);

                        account.Schedules.Remove(toRemove);
                        _context.Schedules.RemoveRange(toRemove); // To remove from DB
                        account.Updated = DateTime.UtcNow;
                        _context.Accounts.Update(account);
                        _context.SaveChanges();
                        _hubContext.Clients.All.SendUpdate(id);

                        if (autoEmail)
                        {
                            SendEmail2AllRolesAndAdmins(account, toRemove);
                        }
                    }
                    else
                    {
                        log.WarnFormat("Schedule did not exist in the schdule functions for {0}. Date {1} function {2}",
                            account.FirstName, scheduleReq.Date, scheduleReq.UserFunction);
                        throw new AppException("The schedule has been already removed");
                    }
                    transaction.Commit();
                    return _mapper.Map<AccountResponse>(account);
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in MoveSchedule2Pool:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("MoveSchedule2Pool after locking");
                }
            }
        }

        public AccountResponse GetScheduleFromPool(string id, UpdateScheduleRequest scheduleReq)
        {

            log.Info("GetScheduleFromPool before locking");
            semaphoreObject.Wait();
            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    log.Info("GetScheduleFromPool removing: " + scheduleReq.Date + "/" + scheduleReq.UserFunction + " from pool");

                    var account = getAccount(id);

                    var poolElement = PopFromPool(account, scheduleReq);

                    if (poolElement != null)
                    {
                        // Schedule not found in the current functions - create one
                        Schedule schedule = new Schedule();
                        schedule.Date = poolElement.Date;
                        schedule.UserFunction = poolElement.UserFunction;
                        schedule.Email = account.Email;
                        schedule.Dob = account.DOB;
                        schedule.UserAvailability = scheduleReq.UserAvailability;
                        schedule.Required = scheduleReq.Required;
                        schedule.ScheduleGroup = scheduleReq.ScheduleGroup == null ? "" : scheduleReq.ScheduleGroup;


                        account.Schedules.Add(schedule);
                        _context.Accounts.Update(account);
                        _context.SaveChanges();
                        _hubContext.Clients.All.SendUpdate(id);

                        AccountResponse response = _mapper.Map<AccountResponse>(account);

                        transaction.Commit();

                        return response;
                    }
                    else
                    {
                        // Pool element not found - do nothing for now
                        log.Info("GetScheduleFromPool got NULL from Pool elements");
                        account = null;
                        throw new AppException("The schedule has been already taken");
                    }
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in GetScheduleFromPool:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("GetScheduleFromPool after locking");
                }
            }
        }
        public SchedulePoolElementsResponse GetAllAvailablePoolElements()
        {
            SchedulePoolElementsResponse response = new SchedulePoolElementsResponse();
            log.Info("GetAllAvailablePoolElements before locking");
            semaphoreObject.Wait();
            try
            {
                response.SchedulePoolElements = _context.SchedulePoolElements.ToList();
            }
            finally
            {
                semaphoreObject.Release();
                log.Info("GetAllAvailablePoolElements after locking");
            }

            return response;
        }

        public SchedulePoolElementsResponse GetAvailablePoolElementsForAccount(string id)
        {
            SchedulePoolElementsResponse response = new SchedulePoolElementsResponse();
            log.Info("GetAvailablePoolElementsForAccount before locking");
            semaphoreObject.Wait();
            try
            {
                var account = getAccount(id);
                List<SchedulePoolElement> list = new List<SchedulePoolElement>();

                foreach (var poolElement in _context.SchedulePoolElements.ToList())
                {
                    foreach (var function in account.UserFunctions)
                    {
                        if (function.UserFunction == poolElement.UserFunction)
                        {
                            list.Add(poolElement);
                            break;
                        }
                    }
                }
                response.SchedulePoolElements = list;
            }
            finally
            {
                semaphoreObject.Release();
                log.Info("GetAvailablePoolElementsForAccount after locking");
            }
            return response;
        }
        public SchedulePoolElement RemoveFromPool(int id, string email, string userFunction)
        {
            log.Info("GetScheduleFromPool before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var schedulePoolAll = _context.SchedulePoolElements.ToList();
                    SchedulePoolElement poolElement = null;
                    foreach (var elem in schedulePoolAll)
                    {
                        if (id == elem.Id && email == elem.Email && userFunction == elem.UserFunction)
                        {
                            poolElement = elem;
                            break;
                        }
                    }
                    if (poolElement != null)
                    {
                        _context.SchedulePoolElements.Remove(poolElement);
                        _context.SaveChanges();
                        transaction.Commit();
                        return poolElement;
                    }
                    else
                    {
                        transaction.Commit();
                        return null;
                    }
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in RemoveFromPool:", ex);
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("GetScheduleFromPool after locking");
                }
            }
            return null;
        }
        public void Delete(string id)
        {
            log.Info("Delete before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var account = getAccount(id);

                    _context.Accounts.Remove(account);
                    _context.SaveChanges();
                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in Delete:", ex);
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("Delete after locking");
                }
            }
        }

        public Byte[] DownloadSchedules()
        {
            log.Info("DownloadSchedules before locking");
            semaphoreObject.Wait();

            using (MemoryStream memory = new MemoryStream())
            {
                using (BufferedStream stream = new BufferedStream(memory))
                {
                    // Initialize document object
                    PdfWriter writer = new PdfWriter(stream);
                    PdfDocument pdf = new PdfDocument(writer);
                    writer.SetCloseStream(false);

                    pdf.SetDefaultPageSize(PageSize.A4.Rotate());
                    Document document = new Document(pdf);
                    
                    using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
                    {
                        try
                        {
                            List<ScheduleDateTime> dateTimeList = GetAllDatesWithoutLock().ScheduleDateTimes;

                            List<ScheduleDateTime> sortedList = dateTimeList;
                            var scheduleDateTimeComparer = new Comparison<ScheduleDateTime>(AccountService.CompareScheduleDateTime);
                            sortedList.Sort(scheduleDateTimeComparer);

                            int index = 0;
                            foreach (ScheduleDateTime dateTime in sortedList)
                            {
                                List<DateFunctionTeam> dateFunctionTeams = GetTeamsByFunctionForDateWithoutLock(dateTime.Date).DateFunctionTeams;
                                Paragraph dateParagraph = new Paragraph(dateTime.Date)
                                       .SetTextAlignment(TextAlignment.CENTER)
                                       .SetFontSize(20).SetMultipliedLeading(1.0f);
                                document.Add(dateParagraph);

                                var date = DateTime.ParseExact(dateTime.Date, ConstantsDefined.DateTimeFormat, CultureInfo.InvariantCulture);
                                Paragraph day = new Paragraph(date.DayOfWeek.ToString())
                                       .SetTextAlignment(TextAlignment.CENTER)
                                       .SetFontSize(20).SetMultipliedLeading(1.0f);
                                document.Add(day);

                                List<DateFunctionTeam> sortedDateFunctionTeams = dateFunctionTeams.OrderBy(o => o.UserFunction).ToList();
                                foreach (DateFunctionTeam team in sortedDateFunctionTeams)
                                {
                                    Paragraph header = new Paragraph(team.UserFunction)
                                           .SetTextAlignment(TextAlignment.LEFT)
                                           .SetFontSize(15).SetMultipliedLeading(1.0f);
                                    document.Add(header);
                                    Table table = new Table(UnitValue.CreatePercentArray(5)).UseAllAvailableWidth();
                                    table.SetKeepTogether(true);
                                    table.SetMarginBottom(10);
                                    

                                    var boldFont = PdfFontFactory.CreateFont(iText.IO.Font.Constants.StandardFonts.TIMES_ROMAN);
                                    var color = new DeviceRgb(210, 210, 210);
                                    iText.Layout.Style style = new iText.Layout.Style()
                                        .SetBackgroundColor(new DeviceRgb(210, 210, 210))
                                        .SetFont(boldFont);
                                    //table.AddHeaderCell(new Paragraph().AddStyle(style).Add(new Text("Task")));
                                    table.AddHeaderCell(new Paragraph().AddStyle(style).Add(new Text("First Name")));
                                    table.AddHeaderCell(new Paragraph().AddStyle(style).Add(new Text("Second Name")));
                                    table.AddHeaderCell(new Paragraph().AddStyle(style).Add(new Text("E-mail")));
                                    table.AddHeaderCell(new Paragraph().AddStyle(style).Add(new Text("DOB")));
                                    table.AddHeaderCell(new Paragraph().AddStyle(style).Add(new Text("Group")));

                                    foreach (User user in team.Users)
                                    {
                                        iText.Layout.Element.Cell cell = new iText.Layout.Element.Cell(1, 1);
                                        //cell.Add(new Paragraph(new Text(user.Function)));
                                        //table.AddCell(cell);

                                        cell = new iText.Layout.Element.Cell(1, 1);
                                        cell.Add(new Paragraph(new Text(user.FirstName)));
                                        table.AddCell(cell);

                                        cell = new iText.Layout.Element.Cell(1, 1);
                                        cell.Add(new Paragraph(new Text(user.LastName)));
                                        table.AddCell(cell);

                                        cell = new iText.Layout.Element.Cell(1, 1);
                                        cell.Add(new Paragraph(new Text(user.Email)));
                                        table.AddCell(cell);

                                        cell = new iText.Layout.Element.Cell(1, 1);
                                        cell.Add(new Paragraph(new Text(user.DOB)));
                                        table.AddCell(cell);

                                        cell = new iText.Layout.Element.Cell(1, 1);
                                        cell.Add(new Paragraph(new Text(user.ScheduleGroup)));
                                        table.AddCell(cell);
                                    }
                                    document.Add(table);
                                }
                                index++;
                                if(index < sortedList.Count)
                                    document.Add(new AreaBreak());
                            }
                            document.Close();
                            stream.Position = 0;

                            MemoryStream memoryPaginated = new MemoryStream();
                            ManipulatePdf(memory, memoryPaginated);

                            return memoryPaginated.GetBuffer();
                        }
                        catch (Exception ex)
                        {
                            transaction.Rollback();
                            Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                            log.Error(Thread.CurrentThread.Name + "Error occurred in DownloadSchedules:", ex);
                            throw;
                        }
                        finally
                        {
                            semaphoreObject.Release();
                            log.Info("DownloadSchedules after locking");
                        }
                    }
                }
            }
        }

        public List<AgentTaskConfig> GetAllAgentTaskConfigs()
        {
            log.Info("GetAllAgentTaskConfigs before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    transaction.Commit();
                    return _context.AgentTaskConfigs.ToList();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in GetAllAgentTaskConfigs:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("GetAllAgentTaskConfigs after locking");
                }
            }
        }
        public AgentTaskConfig[] UpdateAgentTaskConfig(string id, UpdateAgentTaskConfigRequest agentTaskConfigReq)
        {
            log.Info("CreateAgentTaskConfig before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    AgentTaskConfig cfg = _context.AgentTaskConfigs.Where(task => task.AgentTaskStr.Equals(agentTaskConfigReq.AgentTaskStr)).SingleOrDefault();
                    if(cfg == null) // Agent task def not found
                    {
                        cfg = agentTaskConfigReq;
                        _context.AgentTaskConfigs.Add(cfg);
                    } else
                    {
                        cfg.IsGroup = agentTaskConfigReq.IsGroup;
                        _context.AgentTaskConfigs.Update(cfg);
                    }
                    _context.SaveChanges();
                    transaction.Commit();
                    return _context.AgentTaskConfigs.ToArray();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in CreateAgentTaskConfig:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("CreateAgentTaskConfig after locking");
                }
            }
        }
        public void DeleteAgentTaskConfig(string id)
        {
            log.InfoFormat("DeleteAgentTaskConfig before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    AgentTaskConfig cfg = _context.AgentTaskConfigs.Where(task => task.AgentTaskStr.Equals(id)).SingleOrDefault();
                    Debug.Assert(cfg != null, "Configuration for AgentTaskStr="+id+" does not exist");
                    _context.AgentTaskConfigs.RemoveRange(cfg);
                    _context.SaveChanges();
                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.", ex);
                    log.Error(Thread.CurrentThread.Name + "Error occurred in DeleteAgentTaskConfig:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    Console.WriteLine("DeleteAgentTaskConfig after locking");
                }
            }
        }
        public void DeleteAllAgentTaskConfigs()
        {
            log.Info("DeleteAllAgentTaskConfigs before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var foundAgentTaskConfigs = _context.AgentTaskConfigs.ToArray().ToList();
                    _context.AgentTaskConfigs.RemoveRange(foundAgentTaskConfigs);

                    _context.SaveChanges();
                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in DeleteAllAgentTaskConfigs:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("DeleteAllAgentTaskConfigs after locking");
                }
            }
        }

        public void UploadUserAccounts(string path)
        {
            try
            {
                var accounts = _context.Accounts;
                foreach (var account in accounts)
                {
                    if (account.Role != Role.Admin)
                    {
                        Delete(account.Id);
                    }
                }
                PopulateUsers(path);
            }
            catch (Exception ex)
            {
                Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                log.Error(Thread.CurrentThread.Name + "Error occurred in UploadAccounts:", ex);
                throw;
            }
            finally
            {
                log.Info("UploadAccounts after locking");
            }
        }
        public Boolean GenerateSchedules()
        {
            DeleteAllSchedules();

            log.Info("UploadTimeSlots before locking");
            semaphoreObject.Wait();

            try
            {
                /* Create output file*/
                string folderName = "Upload";
                string contentRootPath = _hostingEnvironment.ContentRootPath;
                string newPath = System.IO.Path.Combine(contentRootPath, folderName);
                if (!Directory.Exists(newPath))
                {
                    Directory.CreateDirectory(newPath);
                }

                string inputfullPath = System.IO.Path.Combine(newPath, A2T_INPUT);
                string outputfullResultPath = System.IO.Path.Combine(newPath, A2T_OUTPUT);
                System.IO.File.Delete(inputfullPath);
                System.IO.File.Delete(outputfullResultPath);
                using (var resultStream = new StreamWriter(inputfullPath))
                {
                    WriteAgents2TasksInputFile(resultStream);
                    WriteTimeSlots2Tasks2InputFile(resultStream);
                }
                Runa2tExeAsync(inputfullPath, outputfullResultPath);
                CreateSchedulesFromOutput(outputfullResultPath);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                log.Error(Thread.CurrentThread.Name + "Error occurred in UploadAccounts:", ex);
                throw;
            }
            finally
            {
                log.Info("UploadAccounts after locking");
                semaphoreObject.Release();
            }
        }

        public TimeSlotTasks[] GetTimeSlotsTasks()
        {
            log.Info("GetTimeSlotsTasks before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var response = _context.TimeSlotsTasks.ToArray();
                    return response;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in GetTimeSlotsTasks:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("GetTimeSlotsTasks after locking");
                }
            }
        }

        public TimeSlotTasks[] SetTimeSlotsTasks(TimeSlotTasks slotFromClient)
        {
            log.Info("SetTimeSlotsTasks before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                var slot = _context.TimeSlotsTasks
                                  .Where(task => task.Date.Equals(slotFromClient.Date)).FirstOrDefault();
                try
                {
                    if(slot == null)
                    {
                        _context.TimeSlotsTasks.Add(slotFromClient);
                    } else
                    {
                        slot.Tasks = slotFromClient.Tasks;
                    }
                    _context.SaveChanges();
                    transaction.Commit();
                    var response = _context.TimeSlotsTasks.ToArray();
                    return response;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in SetTimeSlotsTasks:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("SetTimeSlotsTasks after locking");
                }
            }
        }

        public Boolean DeleteTimeSlotsTasks(TimeSlotTasks slotFromClient)
        {
            log.Info("DeleteTimeSlotsTasks before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                var slot = _context.TimeSlotsTasks
                                  .Where(task => task.Date.Equals(slotFromClient.Date)).FirstOrDefault();
                try
                {
                    _context.TimeSlotsTasks.Remove(slot);
                    _context.SaveChanges();
                    transaction.Commit();
                    var response = true;// _context.TimeSlotsTasks.ToList();
                    return response;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in DeleteTimeSlotsTasks:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("DeleteTimeSlotsTasks after locking");
                }
            }
        }
        public void ImportTimeSlotsTasks(string xlsmfullPath)
        {
            DeleteAllTimeSlots();

            // Creates workbook
            Workbook workbook = new Workbook(xlsmfullPath);

            //Gets first worksheet
            Worksheet worksheet = workbook.Worksheets[0];

            // Print worksheet name
            Console.WriteLine("Worksheet: " + worksheet.Name);

            // Get number of rows and columns
            int rows = worksheet.Cells.MaxDataRow;
            int cols = worksheet.Cells.MaxDataColumn;

            /* Sort all timeslots by date 
             */
            object[][] timeslots = new object[rows + 1][];
            for (int row = 0; row <= rows; row++)
            {
                timeslots[row] = new object[cols + 1];
                for (int col = 0; col <= cols; col++)
                {
                    timeslots[row][col] = worksheet.Cells[row, col].Value;
                }
            }
            var sortedByDateVal = timeslots.OrderBy(y =>
            {
                var a = y[0];
                var b = y[1];
                return y[0];
            }).ToArray();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    /* Output timeslots to the DB
                    */
                    for (int row = 0; row <= rows; row++)
                    {
                        TimeSlotTasks timeSlot = new TimeSlotTasks();
                        /* Write time slots - see "Timeslot Specification" - it is almost 1:1 to the input file */
                        for (int col = 0; col <= cols; col++)
                        {
                            if (col == 0)
                            {
                                DateTime dateTime = (DateTime)sortedByDateVal[row][col];
                                timeSlot.Date = dateTime.ToString(ConstantsDefined.DateTimeFormat);
                            }
                            else
                            {
                                /* col == 1 */
                                var functionsStr = (string)sortedByDateVal[row][col];
                                functionsStr = (functionsStr == null) ? string.Empty : functionsStr.Trim();
                                string[] functions = functionsStr == string.Empty ? new string[0] : functionsStr.Split(null);
                                functions = functions.Where(x => !string.IsNullOrEmpty(x)).ToArray();
                                if (functions.Length <= 0)
                                    throw new AppException(String.Format("There must be at least one UserFunction defined at row {0}", row + 1));

                                foreach (var functionStr in functions)
                                {
                                    string fStr = functionStr.Trim();
                                    // Function (task) must be either task or group task
                                    if (!GetTasksArray().Contains(fStr) && !GetGroupTasksArray().Contains(fStr))
                                        throw new AppException(String.Format("UserFunction '{1}' invalid at row {0}", row + 1, fStr));
                                }
                                timeSlot.Tasks = String.Join(" ", functions);
                            }
                        }
                        _context.TimeSlotsTasks.Add(timeSlot);

                    }
                    _context.SaveChanges();
                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in WriteTimeSlots2TasksInputFile:", ex);
                    throw;
                }
                //finally
                //{
                //    semaphoreObject.Release();
                //    log.Info("WriteTimeSlots2TasksInputFile after locking");
                //}
            }
        }

        protected void ManipulatePdf(MemoryStream src, MemoryStream dest)
        {
            PdfDocument pdfDoc = new PdfDocument(new PdfReader(src), new PdfWriter(dest));
            Document doc = new Document(pdfDoc);

            int numberOfPages = pdfDoc.GetNumberOfPages();
            for (int i = 1; i <= numberOfPages; i++)
            {
                // Write aligned text to the specified by parameters point
                doc.ShowTextAligned(new Paragraph("Page " + i + " of " + numberOfPages),
                        559, 806, i, TextAlignment.RIGHT, VerticalAlignment.TOP, 0);
            }

            doc.Close();
        }

        private string[] GetTasksArray()
        {
            var tasks = _context.AgentTaskConfigs.Where(task => task.IsGroup == false).ToArray();
            return tasks.Select(task => task.AgentTaskStr).ToArray();//new List<string>();
        }

        private string[] GetGroupTasksArray()
        {
            var tasks = _context.AgentTaskConfigs.Where(task => task.IsGroup == true).ToArray();
            return tasks.Select(task => task.AgentTaskStr).ToArray();// new List<string>();
        }
        private void WriteAgents2TasksInputFile(StreamWriter resultStream)
        {
            StringBuilder outputString = new StringBuilder();

            WriteAgentRecords(outputString);
            // Output group agent
            WriteGroupAgentRecords(outputString);

            resultStream.WriteLine(outputString.ToString());
            resultStream.WriteLine("\n");

        }

        private void WriteAgentRecords(StringBuilder outputString)
        {
            // Output agent specification
            /* From conversation with James - issue #36
             * "I suggest that, instead of sprinkling the family members at random through the input, 
             * you should place them together early in the input."
             */
            var accounts = _context.Accounts.Include(x => x.UserFunctions).OrderBy(a => a.Email).ToList();
            List<KeyValuePair<string, List<Account>>> agentsSortedByFamily = SortAgentByFamily(accounts);

            foreach (var kvp in agentsSortedByFamily)
            {
                foreach (var account in kvp.Value/*accounts*/)
                {
                    if (account.Role != Role.Admin)
                    {
                        /* Write agent to task records  - See "Agent Specification" */
                        StringBuilder lineWithoutTasks = new StringBuilder();
                        // Agent name + cost
                        lineWithoutTasks.Append("a ").Append(account.Email).Append(SEPARATOR).Append(account.DOB).Append(" ").Append("1").Append(" ");

                        // Agent family
                        lineWithoutTasks.Append(account.Email);

                        /* Tasks */
                        StringBuilder taskString = new StringBuilder();
                        
                        var arr = new ArrayList();

                        for (int i = 0; i < account.UserFunctions.Count; i++)
                        {
                            if (!arr.Contains(account.UserFunctions[i].UserFunction))
                            {
                                taskString.Append(" ").Append(account.UserFunctions[i].UserFunction);
                            }
                            arr.Add(account.UserFunctions[i].UserFunction);
                        }
                        if (taskString.Length > 0)
                        {
                            outputString.Append(lineWithoutTasks.ToString()).Append(taskString).Append("\n");
                        }
                    }
                }
            }
        }

        private List<KeyValuePair<string, List<Account>>> SortAgentByFamily(List<Account> accounts)
        {
            /* Sorted map - so the families are together and in order of number */
            var map = new Dictionary<string, List<Account>>();
            foreach (var account in accounts)
            {
                if (account.Role != Role.Admin)
                {
                    /* Retrieve family name (as a key) belonging to group task (A/B/C ect) */
                    var key = account.Email;
                    if (map.ContainsKey(key))
                    {
                        var list = map.GetValueOrDefault(key);
                        list.Add(account);
                    }
                    else
                    {
                        var l = new List<Account>();
                        l.Add(account);
                        map.Add(key, l);
                    }
                }
            }
            List<KeyValuePair<string, List<Account>>> sortedKeyValuePairs = map
                    .OrderByDescending(kvp => kvp.Value.Count) // OrderByDescending if higher counts needed first
                    .ToList();

            return sortedKeyValuePairs;
        }

        private void WriteGroupAgentRecords(StringBuilder outputString)
        {
            foreach(string tg in GetGroupTasksArray())
            {
                /* groupTaskAccount e.g. "Cleaner" */
                var groupTaskAccounts = _context.Accounts
                                  .Include(x => x.UserFunctions)
                                  .Where(account => account.UserFunctions
                                                           .Any(uf => uf.UserFunction.Equals(tg)))
                                  .ToArray();

                /* Sorted map - so the groups are in the order A/B/C etc*/
                var map = new SortedDictionary<string, List<Account>>(); // Group -> List<Account>

                /* Build tree of groupAgent belonging to specific group (e.g. A/B/C or D)
                 *  a
                 *      -> asmith@gmail.com&1998-06-07
                 *      -> rejkid@gmail.com&1961-03-24
                 *      -> ismith@gmail.com&1961-07-02
                 *  b
                 *      -> awhite@gmail.com&1998-06-07
                 *      -> iblack@gmail.com&1961-07-02
                 *      -> iwhite@gmail.com&1961-07-02
                 *      -> ablack@gmail.com&1998-06-07
                 *  c
                 *      -> mwalsh@gmail.com&2010-01-01
                 *  d
                 *      -> example@gmail.com&1961-03-24
                 *      
                 */
                foreach (var account in groupTaskAccounts)
                {
                    /* Retrieve Group name (as a key) belonging to group task (A/B/C ect) */
                    //var key = account.UserFunctions.Where(uf => uf.UserFunction.Equals(tg)).FirstOrDefault().Group;
                    var accountAgentTasks = account.UserFunctions.Where(uf => uf.UserFunction.Equals(tg)).ToList();
                    foreach (AgentTask agentTask in accountAgentTasks) 
                    {
                        if (map.ContainsKey(agentTask.Group))
                        {
                            var list = map.GetValueOrDefault(agentTask.Group);
                            list.Add(account);
                        }
                        else
                        {
                            var l = new List<Account>();
                            l.Add(account);
                            map.Add(agentTask.Group, l);
                        }
                    }
                }
                /*  Write Group Agent - see "Group Agent Specification" */
                foreach (var keyValuePair in map)
                {
                    outputString.Append("g").Append(" ").Append(keyValuePair.Key).Append(" ").Append(tg);
                    /*
                     * "To obtain more efficient assignments list the more flexible agents in a group last" - 
                     * stated by James Bremner
                     */
                    keyValuePair.Value.Sort((Account a1, Account a2) => {
                        return a1.UserFunctions.Count.CompareTo(a2.UserFunctions.Count);
                    });
                    foreach (var a in keyValuePair.Value)
                    {
                        // Add agent name (agent name = email + dob)
                        outputString.Append(" ").Append(a.Email).Append(SEPARATOR).Append(a.DOB).Append(" ");
                    }
                    outputString.Append("\n");
                }
            }
        }

        private void WriteTimeSlots2Tasks2InputFile(StreamWriter resultStream)
        {
            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var response = _context.TimeSlotsTasks.ToList();
                    StringBuilder sb = new StringBuilder();
                    foreach (var item in response)
                    {
                        sb.Append("t ");
                        DateTime dateTime = DateTime.ParseExact(item.Date, ConstantsDefined.DateTimeFormat,
                                       System.Globalization.CultureInfo.InvariantCulture);
                        sb.Append(dateTime.ToString(AGENTS_2_TASKS_FORMAT) + " ");
                        sb.Append(item.Tasks);
                        resultStream.WriteLine(sb.ToString());
                        sb.Clear();
                    }
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in WriteTimeSlots2Tasks2InputFile:", ex);
                    throw;
                }
            }
        }

        private void Runa2tExeAsync(string inputfullPath, string outputfullResultPath)
        {

            string a2tExePath = System.IO.Path.Combine(Directory.GetCurrentDirectory(), A2T_EXE);

            var result = Cli.Wrap(a2tExePath)
                            .WithArguments(new[] { inputfullPath, outputfullResultPath })
                            .WithWorkingDirectory(System.IO.Path.Combine(Directory.GetCurrentDirectory()))
                            .WithValidation(CommandResultValidation.None)
                            .ExecuteAsync().GetAwaiter().GetResult()
                            ;
            log.Info("Result=" + result);
            if (result.ExitCode != 0)
            {
                switch (result.ExitCode)
                {
                    case 3:
                        throw new AppException("Bad command line parameters");
                    case 10:
                        throw new AppException("Timeslot badly formatted");
                    case 11:
                        throw new AppException("Timeslots out of order");
                    case 12:
                        throw new AppException("Duplicate agent name");
                    case 13:
                        throw new AppException("Duplicate timeslot");
                    case 14:
                        throw new AppException("Cannot open output file");
                    case 15:
                        throw new AppException("Cannot open input file");
                    case 16:
                        throw new AppException("Unit test failed");
                    case 17:
                        throw new AppException("Timeslot conversion overflow");
                    case 20:
                        throw new AppException("Cannot parse timeslot timestamp");
                    case 21:
                        throw new AppException("Cannot open log file");
                    case 22:
                        throw new AppException("No timeslots specified");
                    case 23:
                        throw new AppException("Duplicate group member");
                    case 25:
                        throw new AppException("Unspecified group member");
                    default:
                        throw new AppException("Unknown Agents2Tasks Error");
                }
            }
        }

        private void CreateSchedulesFromOutput(string outputFile)
        {
            //log.Info("CreateSchedulesFromOutput before locking");
            //semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    using (var resultStream = new StreamReader(outputFile))
                    {
                        string line;
                        while ((line = resultStream.ReadLine()) != null)
                        {
                            line.Trim();
                            if (line.StartsWith("A"))
                            {
                                log.Info("Read: " + line);
                                if (line.Contains("_group"))
                                {
                                    // This is lead agent name - skip it - see "File format" documentation by James Bremner
                                    continue;
                                }

                                var lineComponents = line.Split(" ");

                                Debug.Assert(lineComponents.Length >= 5);
                                var dateStr = DateTime.ParseExact(lineComponents[1], AGENTS_2_TASKS_FORMAT,
                                                        CultureInfo.InvariantCulture).ToString(ConstantsDefined.DateTimeFormat);

                                string[] accountComponents;
                                string emailStr;
                                string dobStr;
                                var functionStr = string.Empty;
                                var groupStr = string.Empty;
                                if (lineComponents.Length >= 7) // e.g. Cleaner/Welcomer ect
                                {
                                    // 7 element record
                                    groupStr = lineComponents[4];
                                    functionStr = lineComponents[6];
                                    accountComponents = lineComponents[2].Split("&");
                                    emailStr = accountComponents[0];
                                    dobStr = accountComponents[1];
                                }
                                else
                                {
                                    Debug.Assert(lineComponents.Length == 5);
                                    // 5 element record
                                    functionStr = lineComponents[4];
                                    accountComponents = lineComponents[2].Split("&");
                                    emailStr = accountComponents[0];
                                    dobStr = accountComponents[1];
                                }

                                Account account = _context.Accounts.Include(x => x.Schedules).Include(x => x.UserFunctions).SingleOrDefault(x => x.Email == emailStr && x.DOB == dobStr);
                                Debug.Assert(account != null, "Record not found");

                                Console.WriteLine($"{dateStr}");

                                Schedule schedule = new Schedule
                                {
                                    Date = dateStr,
                                    Email = emailStr,
                                    ScheduleGroup = groupStr.Length != 0 ? groupStr : account.UserFunctions.Where(uf => uf.UserFunction.Equals(functionStr)).FirstOrDefault().Group,
                                    UserFunction = functionStr,
                                    Dob = dobStr,
                                };
                                account.Schedules.Add(schedule);
                                _context.Accounts.Update(account);
                            }
                        }
                    }

                    _context.SaveChanges();
                    transaction.Commit();
                    //Thread.Sleep(1000 * 30);
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in CreateSchedulesFromOutput:", ex);
                    throw;
                }
                finally
                {
                    //semaphoreObject.Release();
                    //log.Info("CreateSchedulesFromOutput after locking");
                }
            }
        }

        public IEnumerable<AccountResponse> DeleteAllUserAccounts()
        {
            log.Info("DeleteAllUserAccounts before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var foundAccounts = _context.Accounts.Include(x => x.RefreshTokens).Include(x => x.Schedules).Include(x => x.UserFunctions).Where(x => x.Role != Role.Admin).ToArray().ToList();
                    _context.Accounts.RemoveRange(foundAccounts);

                    _context.SaveChanges();
                    transaction.Commit();

                    var accounts = _context.Accounts;
                    return _mapper.Map<IList<AccountResponse>>(accounts);
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in Delete:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("Delete after locking");
                }
            }
        }
         
        private void PopulateUsers(string path)
        {
            //Creates workbook
            Workbook workbook = new Workbook(path);

            //Gets first worksheet
            Worksheet worksheet = workbook.Worksheets[0];

            // Print worksheet name
            Console.WriteLine("Worksheet: " + worksheet.Name);

            // Get number of rows and columns
            int rows = worksheet.Cells.MaxDataRow;
            int cols = worksheet.Cells.MaxDataColumn;

            Dictionary<string, List<AgentTask>> user2Functions = new ();
            List<AgentTask> functions = new List<AgentTask>();
            CreateRequest request = new CreateRequest();

            log.Info("PopulateUsers before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    // Loop through rows
                    for (int row = 0; row <= rows; row++)
                    {
                        // Create user request
                        CreateUser(worksheet, cols, row, request, functions);

                        /* Sanity check that each group task (e.g. Cleaner/Choir...) has some group specified (e.g. A or B etc) */
                        foreach (string gt in GetGroupTasksArray())
                        {
                            AgentTask func = functions.SingleOrDefault(fr => fr.UserFunction.Equals(gt));
                            if (func != null)
                            {
                                if (func.Group.Trim().Length == 0)
                                {
                                    throw new AppException(String.Format("Group task {1} at row {0} has not defined Team Group", row + 1, func.UserFunction));
                                }
                            }
                        }


                        // User and functions have been red in
                        request.Role = Role.User.ToString();

                        Account account = _context.Accounts.SingleOrDefault(x => x.Email == request.Email && x.DOB == request.Dob);
                        // Validate
                        if (account == null)
                        {
                            // Account does not exist yet - create one
                            // map model to new account object
                            account = _mapper.Map<Account>(request);
                            account.Created = DateTime.UtcNow;
                            account.Verified = DateTime.UtcNow;

                            // hash password
                            account.PasswordHash = BC.HashPassword(request.Password);

                            account.UserFunctions = new List<Entities.AgentTask>();
                            account.Schedules = new List<Schedule>();
                            var result = _userManager.CreateAsync(account).GetAwaiter().GetResult();
                            Debug.Assert(result != null && IdentityResult.Success.Succeeded == result.Succeeded);
                        }

                        // Initialize function - multiple function per row
                        account.UserFunctions.AddRange(functions);

                        // Collect all agent tasks objects and keep them in the map per user(account == dob+email)
                        if (user2Functions.ContainsKey(account.DOB + account.Email))
                        {
                            user2Functions.GetValueOrDefault(account.DOB + account.Email).AddRange(functions);
                        }
                        else
                        {
                            List<AgentTask> tasks = new List<AgentTask>();
                            tasks.AddRange(functions);
                            user2Functions.Add(account.DOB + account.Email, tasks);
                        }
                        CheckGroupAgentPreferredTimeConsistent(user2Functions, row);
                        // End of collecting agent tasks

                        _context.Accounts.Update(account);
                        functions.Clear();
                    }
                    _context.SaveChanges();
                    transaction.Commit();
                    //Thread.Sleep(1000 * 30);
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in Create:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("PopulateUsers after locking");
                }
            }
        }

        private void CheckGroupAgentPreferredTimeConsistent(Dictionary<string, List<AgentTask>> user2Functions, int row)
        {
            foreach (string gt in GetGroupTasksArray())
            {
                var uniqueTasks = user2Functions
                .SelectMany(account => account.Value).Where(uf => uf.UserFunction.Equals(gt)).ToList()
                    .Distinct(
                    new CustomEqualityComparer<AgentTask>((agent1, agent2) =>
                    {
                        return agent1.Equals(agent2);
                    }))
                    .ToArray();

                if (gt == "Cleaner" && uniqueTasks.Length == 4)
                {
                    Console.WriteLine(uniqueTasks.Length);
                }
                else if (gt == "Welcomer" && uniqueTasks.Length == 3)
                {
                    Console.WriteLine(uniqueTasks.Length);
                }
                else if (gt == "Choir" && uniqueTasks.Length == 2)
                {
                    Console.WriteLine(uniqueTasks.Length);
                }
                else if (gt == "Collector" && uniqueTasks.Length == 1)
                {
                    Console.WriteLine(uniqueTasks.Length);
                }
                for (int i = 0; i < uniqueTasks.Length; i++)
                {
                    /* Check that the group tasks are consistent, that is all agents within the 'group agent' have the same
                    * preferred time.
                    */

                    var tasks = user2Functions
                                .SelectMany(account => account.Value).Where(uf => uf.Equals(uniqueTasks[i])).ToArray();
                    if (tasks.Length > 1) // if we have group agent with at least two members
                    {
                        for (int j = 0; j < tasks.Length; j++)
                        {
                            if (uniqueTasks[i].PreferredTime != tasks[j].PreferredTime)
                            {
                                throw new AppException(String.Format("Group Agent {0} at row {1} has inconsistent time: {2} (Prev:{3})",
                                    tasks[j].Group,
                                    row + 1,
                                    tasks[j].PreferredTime,
                                    uniqueTasks[i].PreferredTime));
                            }
                        }
                    }
                }
            }
        }

        private void CreateUser(Worksheet worksheet, int noOfCols, int row, CreateRequest request, List<AgentTask> functions)
        {
            AgentTask function = new AgentTask();
            // Loop through each column in selected row
            for (int col = 0; col <= noOfCols; col++)
            {
                switch (col)
                {
                    case 0:
                        {
                            request.Title = (string)worksheet.Cells[row, col].Value;
                            request.Title = (request.Title == null) ? string.Empty : request.Title.Trim();
                            if (request.Title.Length <= 0)
                                throw new AppException(String.Format("Title can't be empty at row {0}", row + 1));
                        }
                        break;
                    case 1:
                        {
                            request.FirstName = (string)worksheet.Cells[row, col].Value;
                            request.FirstName = (request.FirstName == null) ? string.Empty : request.FirstName.Trim();
                            if (request.FirstName.Length <= 0)
                                throw new AppException(String.Format("First Name can't be empty at row {0}", row + 1));
                        }
                        break;
                    case 2:
                        {
                            request.LastName = (string)worksheet.Cells[row, col].Value;
                            request.LastName = (request.LastName == null) ? string.Empty : request.LastName.Trim();
                            if (request.LastName.Length <= 0)
                                throw new AppException(String.Format("Last Name can't be empty at row {0}", row + 1));
                        }
                        break;
                    case 3:
                        {
                            try
                            {
                                request.Email = (string)worksheet.Cells[row, col].Value;
                                request.Email = (request.Email == null) ? string.Empty : request.Email.Trim();
                                MailAddress m = new MailAddress(request.Email);
                            }
                            catch (Exception)
                            {
                                throw new AppException(String.Format("Email is in wrong format at row {0}", row + 1));
                            }
                        }
                        break;
                    case 4:
                        {
                            request.PhoneNumber = (string)worksheet.Cells[row, col].Value;
                            request.PhoneNumber = (request.PhoneNumber == null) ? string.Empty : request.PhoneNumber.Trim();
                        }
                        break;
                    case 5:
                        {
                            try
                            {
                                DateTime dob = (DateTime)worksheet.Cells[row, col].Value;
                                request.Dob = dob.ToString(ConstantsDefined.DateFormat, System.Globalization.CultureInfo.InvariantCulture);
                            }
                            catch (Exception)
                            {
                                throw new AppException(String.Format("DOB is in wrong format at row {0}", row + 1));
                            }
                        }
                        break;
                    case 6:
                        {
                            request.Password = (string)worksheet.Cells[row, col].Value;
                            request.Password = (request.Password == null) ? string.Empty : request.Password.Trim();

                            request.ConfirmPassword = (string)worksheet.Cells[row, col].Value;
                            request.ConfirmPassword = (request.ConfirmPassword == null) ? string.Empty : request.ConfirmPassword.Trim();

                            if (request.Password.Length == 0)
                                throw new AppException(String.Format("Password can't be empty at row {0}", row + 1));
                        }
                        break;
                    case 7: // Serve 8 as well - group string
                        {
                            var groupStr = worksheet.Cells[row, col + 1].Value == null ? String.Empty : ((string)worksheet.Cells[row, col + 1].Value).Trim();
                            // Add tasks to the user
                            var tasksStr = worksheet.Cells[row, col].Value == null ? String.Empty : ((string)worksheet.Cells[row, col].Value).Trim();

                            string[] tasks = tasksStr == string.Empty ? new string[0] : tasksStr.Split(' ');
                            tasks = tasks.Where(x => !string.IsNullOrEmpty(x)).ToArray();
                            if (tasks.Length <= 0)
                                throw new AppException(String.Format("There must be at least one User Task defined at row {0}", row + 1));

                            if (groupStr.Length > 0)
                            {
                                // We are defining user for a group task
                                if (!GetGroupTasksArray().Contains(tasks[0]))
                                {
                                    throw new AppException(String.Format("Group task '{1}' must be configured in 'GroupTasks' at row {0}", row + 1, tasks[0]));
                                }
                            }
                            else if (!GetTasksArray().Contains(tasks[0]))
                            {
                                throw new AppException(String.Format("Group task '{1}' must be configured in 'Tasks' at row {0}", row + 1, tasks[0]));
                            }
                            /* There should be just one task (function e.g. "Cleaner") for group agent (account) 
                              
                                    Group: "A"
                                    UserFunction : Cleaner
                                    PreferredTime : 8:30

                                    Group: ""
                                    UserFunction : Acolyte
                                    PreferredTime : 8:30

                                    Group: ""
                                    UserFunction : Acolyte
                                    PreferredTime : 10:00
                                    Group: ""
                                    UserFunction : Reader1
                                    PreferredTime : 8:30
                                    Group: ""
                                    UserFunction : EMHC
                                    PreferredTime : 10:00
                             */
                            for (int index = 0; index < tasks.Length; index++)
                            {
                                TimeSpan intervalVal;
                                var functionStr = tasks[index];
                                if (index < (tasks.Length - 1) && IsValidTimeFormat(tasks[index + 1], out intervalVal))
                                {
                                    // We have preferred time specified
                                    index++;
                                }
                                else
                                {
                                    intervalVal = new TimeSpan(0, 0, 0);
                                }
                                AgentTask f = new AgentTask
                                {
                                    UserFunction = functionStr.Trim(),
                                    PreferredTime = $"{intervalVal:hh\\:mm}",
                                    Group = groupStr, // Group string for group task, empty string for the rest
                                };
                                if (!GetTasksArray().Contains(f.UserFunction) && !GetGroupTasksArray().Contains(f.UserFunction))
                                    throw new AppException(String.Format("User UserFunction '{1}' invalid at row {0}", row + 1, f.UserFunction));

                                foreach (var groupTask in GetGroupTasksArray())
                                {
                                    if (groupTask == f.UserFunction)
                                    {
                                        f.IsGroup = true;
                                        break;
                                    }
                                }
                                functions.Add(f);
                            }
                        }
                        break;
                    case 8:
                        break;

                    default:
                        // code block
                        break;
                }
            }
        }

        public class CustomEqualityComparer<T> : IEqualityComparer<T>
        {
            private readonly Func<T, T, bool> Comparison;

            public CustomEqualityComparer(Func<T, T, bool> comparison)
            {
                this.Comparison = comparison;
            }

            public bool Equals(T x, T y)
            {
                return Comparison(x, y);
            }

            public int GetHashCode(T obj)
            {
                return obj.GetHashCode();
            }

            public static IEqualityComparer<T> Create(Func<T, T, bool> comparison)
            {
                return new CustomEqualityComparer<T>(comparison);
            }
        }
        public bool IsValidTimeFormat(string input, out TimeSpan intervalVal)
        {
            //TimeSpan dummyOutput;
            return TimeSpan.TryParse(input, out intervalVal);
        }

        /* Private helper functions */
        private SchedulePoolElement PopFromPool(Account account, UpdateScheduleRequest item)
        {
            var schedulePoolAll = _context.SchedulePoolElements.ToList();
            SchedulePoolElement poolElement = null;
            foreach (var elem in schedulePoolAll)
            {
                // 
                string dateTime = item.Date;
                if (dateTime == elem.Date && /* account.Email == elem.Email && */ item.UserFunction == elem.UserFunction)
                {
                    poolElement = elem;
                    break;
                }
            }
            if (poolElement != null)
            {
                _context.SchedulePoolElements.Remove(poolElement);
                _context.SaveChanges();
                return poolElement;
            }
            else
            {
                return null;
            }
        }
        public Boolean GetAutoEmail()
        {
            log.Info("GetAutoEmail before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var systemInformation = _context.SystemInformation.ToList().FirstOrDefault();
                    _context.Entry(systemInformation).Reload();
                    var retval = systemInformation.autoEmail;
                    return retval;

                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in GetAutoEmail:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("GetAutoEmail after locking");
                }
            }
        }

        public Boolean SetAutoEmail(Boolean autoEmail)
        {
            log.Info("SetAutoEmail before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    var systemInformation = _context.SystemInformation.ToList().FirstOrDefault();
                    systemInformation.autoEmail = autoEmail;
                    _context.SaveChanges();
                    transaction.Commit();
                    return systemInformation.autoEmail;
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    log.Error(Thread.CurrentThread.Name + "Error occurred in SetAutoEmail:", ex);
                    throw;
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("SetAutoEmail after locking");
                }
            }
        }

        public void SendRemindingEmail4Functions()
        {
            log.Info("SendRemindingEmail4Functions before locking");
            semaphoreObject.Wait();

            using (IDbContextTransaction transaction = _context.Database.BeginTransaction())
            {
                try
                {
                    log.Debug("\n");
                    var accountAll = _context.Accounts.Include(x => x.UserFunctions).Include(x => x.Schedules).ToList();

                    IEnumerable<Account> query = accountAll.TakeWhile((a) => a.UserFunctions != null);
                    foreach (var a in accountAll)
                    {
                        foreach (var s in a.Schedules)
                        {
                            string clientTimeZoneId = _configuration["AppSettings:ClientTimeZoneId"];
                            DateTime scheduleDate = DateTime.Parse(s.Date);

                            DateTime dt = DateTime.Now;
                            DateTime now = dt;
                            log.DebugFormat("scheduleDate {0} now {1}",
                                scheduleDate,
                                now);

                            log.DebugFormat("Schedule `{0}` is now {1} days ahead of execution (negative means it's over)",
                                s.Date,
                                (scheduleDate - now).TotalMilliseconds / (1000 * 60 * 60 * 24));

                            if ((scheduleDate - now) < WEEK_TIMEOUT && a.NotifyWeekBefore == true && s.NotifiedWeekBefore == false)
                            {
                                string message = $@"This is a weekly reminder that <row>{a.FirstName} {a.LastName}</row> is scheduled to attend their duties.";
                                string subject = $@"Reminder: {a.FirstName} {a.LastName} is {s.UserFunction} on {scheduleDate.ToString(ConstantsDefined.DateTimeFormat)}";
                                _emailService.Send(
                                    to: a.Email,
                                    subject: subject,
                                    html: message
                                );
                                s.NotifiedWeekBefore = true;
                                log.DebugFormat("Schedule ready for week ahead of reminder for an account is: {0} {1} {2}", a.FirstName, a.LastName, a.Email);
                            }
                            if ((scheduleDate - now) < THREE_DAYS_TIMEOUT && a.NotifyThreeDaysBefore == true && s.NotifiedThreeDaysBefore == false)
                            {
                                string message = $@"This is a three-day reminder that <row>{a.FirstName} {a.LastName}</row> is scheduled to attend their duties.";
                                string subject = $@"Reminder: {a.FirstName} {a.LastName} is {s.UserFunction} on {scheduleDate.ToString(ConstantsDefined.DateTimeFormat)}";
                                _emailService.Send(
                                    to: a.Email,
                                    subject: subject,
                                    html: message
                                );
                                s.NotifiedThreeDaysBefore = true;
                                log.DebugFormat("Schedule ready for 3 days ahead of reminder for an account is: {0} {1} {2}", a.FirstName, a.LastName, a.Email);
                            }
                            _context.Accounts.Update(a);
                            _context.SaveChanges();
                        }
                    }
                    transaction.Commit();
                }
                catch (Exception ex)
                {
                    transaction.Rollback();
                    log.Error(Thread.CurrentThread.Name + "Error occurred in SendRemindingEmail4Functions:", ex);
                    Console.WriteLine(Thread.CurrentThread.Name + "Error occurred.");
                    if (ex.GetType() == typeof(DbUpdateConcurrencyException))
                    {
                        var dbUCException = (DbUpdateConcurrencyException)ex;
                        foreach (var entry in dbUCException.Entries)
                        {
                            if (entry.Entity is Schedule)
                            {
                                var proposedValues = entry.CurrentValues;
                                var databaseValues = entry.GetDatabaseValues();

                                foreach (var property in proposedValues.Properties)
                                {
                                    var proposedValue = proposedValues[property];
                                    var databaseValue = databaseValues[property];

                                    // TODO: decide which value should be written to database
                                    // proposedValues[property] = <value to be saved>;
                                }

                                // Refresh original values to bypass next concurrency check
                                entry.OriginalValues.SetValues(databaseValues);
                            }
                            else
                            {
                                throw new NotSupportedException(
                                    "Don't know how to handle concurrency conflicts for "
                                    + entry.Metadata.Name);
                            }
                        }
                    }
                    //throw; // for now
                }
                finally
                {
                    semaphoreObject.Release();
                    log.Info("SendRemindingEmail4Functions after locking");
                }
            }
        }

        private void PushToPool(Account account, UpdateScheduleRequest item)
        {
            var newPoolElement = new SchedulePoolElement();
            newPoolElement = _mapper.Map<SchedulePoolElement>(item);
            newPoolElement.Email = account.Email;
            newPoolElement.ScheduleGroup = item.ScheduleGroup;
            _context.SchedulePoolElements.Add(newPoolElement);
            _context.SaveChanges();
        }
        private void SendEmail2AllRolesAndAdmins(Account a, Schedule schedule)
        {
            var accountAll = _context.Accounts.ToList();
            foreach (var account in accountAll)
            {
                var clientTimeZoneId = _appSettings.ClientTimeZoneId;
                var scheduleDate = schedule.Date;

                if (account.Role == Role.Admin)
                {
                    string message = $@"<row>{a.FirstName} {a.LastName}</row> is unable to attend their duties on " + scheduleDate;
                    string subject = $@"Warning Administrator: {account.FirstName} {account.LastName}, {schedule.UserFunction}" + " is needed";
                    _emailService.Send(
                        to: account.Email,
                        subject: subject,
                        html: message
                    );
                }

                foreach (var f in account.UserFunctions)
                {
                    if (f.UserFunction == schedule.UserFunction || f.UserFunction == schedule.UserFunction) // TODO second or to be removed
                    {
                        string message = $@"<row>{a.FirstName} {a.LastName}</row> is unable to attend their duties on " + scheduleDate;
                        string subject = $@"{account.FirstName} {account.LastName}, {f.UserFunction}" + " is needed";
                        _emailService.Send(
                            to: account.Email,
                            subject: subject,
                            html: message
                        );
                        break;
                    }
                }
            }
        }
        // helper methods

        private Account getAccount(string id)
        {
            Account account = null;
            var accountAll = _context.Accounts.Include(x => x.RefreshTokens).Include(x => x.Schedules).Include(x => x.UserFunctions)
                    .ToList();
            account = accountAll.Find(x => x.Id == id);
            if (account == null)
            {
                throw new KeyNotFoundException("Account not found");
            }
            return account;
        }

        private (RefreshToken, Account) getRefreshToken(string token)
        {

            var account = _context.Accounts.Include(x => x.RefreshTokens).SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            //var account = _context.Accounts.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            if (account == null)
            {
                throw new AppException("Account null for token:"+ token);
            }
            var refreshToken = account.RefreshTokens.Single(x => x.Token == token);
            if (!refreshToken.IsActive)
            {
                throw new AppException("Account found but token is not active:"+ token);
            }
            return (refreshToken, account);
        }

        private string generateJwtToken(Account account)
        {
            /*
             * Normally the JWT signature is validated on the server (in our case in JwtMiddleware),
             * when the JWT is sent back with each request (in a cookie or in the Authorization header). 
             * This is to validate that the JWT has not been altered. 
             * If the JWT was signed using a secret key, having it in the client puts the secret at risk of exposure
             * - particularly when using a browser-based client such as Angular. If the secret is compromised, 
             * it can then can be used to alter and sign a JWT with changes made.
            */
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", account.Id.ToString()) }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor) as JwtSecurityToken;

            // JD
            var tokenExp = token.Claims.First(claim => claim.Type.Equals("exp")).Value;
            var ticks = long.Parse(tokenExp);
            var tokenDate = DateTimeOffset.FromUnixTimeSeconds(ticks).UtcDateTime;
            var Expires = DateTime.Now.AddMinutes(15);
            log.InfoFormat("JWT Next expiration date for {0} {1} is {2}", account.FirstName, account.LastName, tokenDate.ToLocalTime().ToString());
            // JD
            string jwtToken = tokenHandler.WriteToken(token);
            log.InfoFormat("JWT token {0} for {1} {2}", jwtToken, account.FirstName, account.LastName);
            return jwtToken;
        }
        /* JD Test*/
        private Task<string> GetJWTToken(string user)
        {

            var now = DateTime.UtcNow;
            //constructing part 1: header.Encode()
            JwtHeader jwtHeader = new JwtHeader();
            var sha512 = new HMACSHA512();
            jwtHeader.Add("alg", sha512);
            var partOne = jwtHeader.Base64UrlEncode();

            //constructing part 2: payload.Encode  
            JwtPayload payload = new JwtPayload();
            payload.Add("sub", user);
            payload.Add("exp", ConvertToUnixTimestamp(now.AddMinutes(15)));
            payload.Add("nbf", ConvertToUnixTimestamp(now));
            payload.Add("iat", ConvertToUnixTimestamp(now));
            var partTwo = payload.Base64UrlEncode();

            //constructing part 3: HS512(part1 + "." + part2, key)
            var tobeHashed = string.Join(".", partOne, partTwo);
            var sha = new HMACSHA512(Encoding.UTF8.GetBytes(_appSettings.Secret));
            var hashedByteArray = sha.ComputeHash(Encoding.UTF8.GetBytes(tobeHashed));

            //You need to base64UrlEncode the signature hash value
            var partThree = Base64UrlEncode(hashedByteArray);

            //Now construct the token
            var tokenString = string.Join(".", tobeHashed, partThree);

            //await was not used so no need for `async` keyword. Just return task
            return Task.FromResult(tokenString);
        }
        private static double ConvertToUnixTimestamp(DateTime date)
        {
            DateTime origin = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            TimeSpan diff = date.ToUniversalTime() - origin;
            return Math.Floor(diff.TotalSeconds);
        }
        // from JWT spec
        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }


        private RefreshToken generateRefreshToken(string ipAddress)
        {
            return new RefreshToken
            {
                Token = randomTokenString(),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };
        }

        private void removeOldRefreshTokens(Account account)
        {
            account.RefreshTokens.RemoveAll(x =>
                !x.IsActive &&
                x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
        }

        private string randomTokenString()
        {
            using var rng = RandomNumberGenerator.Create();
            //using var rngCryptoServiceProvider = new RNGCryptoServiceProvider(); // OLD
            var randomBytes = new byte[40];

            rng.GetBytes(randomBytes);
            //rngCryptoServiceProvider.GetBytes(randomBytes); // OLD

            // convert random bytes to hex string
            return BitConverter.ToString(randomBytes).Replace("-", "");
        }

        private void sendVerificationEmail(Account account, string origin)
        {
            string message;

            if (!string.IsNullOrEmpty(origin))
            {
                var verifyUrl = $"{origin}/account/verify-email?token={account.VerificationToken}&DOB={account.DOB}";
                message = $@"<p>Please click the below link to verify your email address:</p>
                             <p><a href=""{verifyUrl}"">{verifyUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to verify your email address with the <code>/accounts/verify-email</code> api route:</p>
                             <p><code>{account.VerificationToken + "&" + account.DOB}</code></p>";
            }

            _emailService.Send(
                to: account.Email,
                subject: "Sign-up Verification API - Verify Email",
                html: $@"<h4>Verify Email</h4>
                         <p>Thanks for registering!</p>
                         {message}"
            );
        }

        private void sendAlreadyRegisteredEmail(string email, string dob, string origin)
        {
            string message;

            if (!string.IsNullOrEmpty(origin))
                message = $@"<p>If you don't know your password please visit the <a href=""{origin}/account/forgot-password"">forgot password</a> page.</p>";
            else
                message = "<p>If you don't know your password you can reset it via the <code>/accounts/forgot-password</code> api route.</p>";

            _emailService.Send(
                to: email,
                subject: "Sign-up Verification API - Email Already Registered",
                html: $@"<h4>Email Already Registered</h4>
                         <p>Your email <strong>{email}</strong> and DOB: {dob} is already registered.</p>
                         {message}"
            );
        }


        private void sendPasswordResetEmail(Account account, string origin)
        {
            string message;

            if (!string.IsNullOrEmpty(origin))
            {
                var resetUrl = $"{origin}/account/reset-password?token={account.ResetToken}&DOB={System.Web.HttpUtility.UrlEncode(account.DOB)}";
                message = $@"<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                             <p><a href=""{resetUrl}"">{resetUrl}</a></p>";
            }
            else
            {
                message = $@"<p>Please use the below token to reset your password with the <code>/accounts/reset-password</code> api route:</p>
                             <p><code>{account.ResetToken + "&" + account.DOB}</code></p>";
            }

            _emailService.Send(
                to: account.Email,
                subject: "Sign-up Verification API - Reset Password",
                html: $@"<h4>Reset Password Email</h4>
                         {message}"
            );
        }
    }
}
