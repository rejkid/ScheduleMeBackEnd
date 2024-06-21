using Aspose.Pdf.Operators;
using AutoMapper;
using iText.Kernel.Pdf;
using iText.Layout;
using iText.Layout.Element;
using iText.Layout.Properties;
using log4net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using WebApi.Entities;
using WebApi.Helpers;
using WebApi.Models.Accounts;
using WebApi.Services;
using static Google.Apis.Requests.BatchRequest;

namespace WebApi.Controllers
{
    public class UserFriendlyException : Exception
    {
        public UserFriendlyException(string message) : base(message) { }
        public UserFriendlyException(string message, Exception innerException) : base(message, innerException) { }
    }

    [ApiController]
    [Route("[controller]")]
    public class AccountsController : BaseController
    {
        #region log4net
        private static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        #endregion //log4net

        private readonly IAccountService _accountService;
        private readonly IMapper _mapper;
        private readonly AppSettings _appSettings;

        private Microsoft.AspNetCore.Hosting.IWebHostEnvironment _hostingEnvironment;

        public AccountsController(
            IAccountService accountService,
            IMapper mapper,
            IOptions<AppSettings> appSettings,
            Microsoft.AspNetCore.Hosting.IWebHostEnvironment hostingEnvironment)
        {
            _accountService = accountService;
            _mapper = mapper;
            _appSettings = appSettings.Value;
            _hostingEnvironment = hostingEnvironment;
        }


        [HttpPost("authenticate")]
        public ActionResult<AuthenticateResponse> Authenticate(AuthenticateRequest model)
        {
            try
            {
                log.InfoFormat("Authenticating user {0} password {1} DOB {2} for ipaddress: {3}",
                    model.Email,
                    model.Password,
                    model.Dob,
                    ipAddress());
                var response = _accountService.Authenticate(model, ipAddress());
                setTokenCookie(response.RefreshToken);

                log.InfoFormat("Setting cookie - response.RefreshToken= {0} for E-mail: {1}",
                    response.RefreshToken,
                    model.Email);

                return Ok(response);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }


        [HttpPost("refresh-token")]
        public ActionResult<AuthenticateResponse> RefreshToken()
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"];

                Console.WriteLine("refreshToken is:" + refreshToken);
                var response = _accountService.RefreshToken(refreshToken, ipAddress());
                setTokenCookie(response.RefreshToken);

                return Ok(response);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpPost("revoke-token")]
        public IActionResult RevokeToken(RevokeTokenRequest model)
        {
            var refreshToken = Request.Cookies["refreshToken"];

            // accept token from request body or cookie
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            // users can revoke their own tokens and admins can revoke any tokens
            if (!Account.OwnsToken(token) && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            _accountService.RevokeToken(token, ipAddress());
            return Ok(new { message = "Token revoked" });
        }

        [HttpPost("register")]
        public IActionResult Register(RegisterRequest model)
        {
            var result = _accountService.Register(model, Request.Headers["origin"]);
            if (result.Succeeded)
            {
                return Ok(new { message = "Registration successful, please check your email for verification instructions" });
            }
            else
            {
                return BadRequest(result.ToString());
            }
        }
        [Authorize(Role.Admin)]
        [HttpPost]
        public ActionResult<AccountResponse> Create(CreateRequest model)
        {
            try
            {
                AccountResponse response = _accountService.Create(model);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message); ;
            }

        }

        [Authorize]
        [HttpPut("{id}")]
        public ActionResult<AccountResponse> Update(string id, AccountRequest model)
        {
            // users can update their own account and admins can update any account
            if (id != Account.Id && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            // only admins can update role
            if (Account.Role != Role.Admin)
                model.Role = null;

            var response = _accountService.Update(id, model);
            return Ok(response);
        }

        [HttpPost("verify-email")]
        public IActionResult VerifyEmail(VerifyEmailRequest model)
        {
            //log.Info("VerifyEmail before calling Parse");
            //DateTime dateTime = DateTime.Parse(model.Dob);
            _accountService.VerifyEmail(model/*model.Token, dateTime*/);
            return Ok(new { message = "Verification successful, you can now login" });
        }

        [HttpPost("forgot-password")]
        public IActionResult ForgotPassword(ForgotPasswordRequest model)
        {
            _accountService.ForgotPassword(model, Request.Headers["origin"]);
            return Ok(new { message = "Please check your email for password reset instructions" });
        }

        [HttpPost("validate-reset-token")]
        public IActionResult ValidateResetToken(ValidateResetTokenRequest model)
        {

            _accountService.ValidateResetToken(model);
            return Ok(new { message = "Token is valid" });
        }

        [HttpPost("reset-password")]
        public IActionResult ResetPassword(ResetPasswordRequest model)
        {
            _accountService.ResetPassword(model);
            return Ok(new { message = "Password reset successful, you can now login" });
        }

        [Authorize(Role.Admin)]
        [HttpGet]
        public ActionResult<IEnumerable<AccountResponse>> GetAll()
        {
            var accounts = _accountService.GetAll();
            return Ok(accounts);
        }

        [Authorize(Role.Admin)]
        [HttpPost("accounts-by-date")]
        public ActionResult<IEnumerable<AccountResponse>> GetAccountsForDateAndTask(AccountsByDateAndTaskDTO accountsByDateAndTaskDTO)
        {
            var accounts = _accountService.GetAccountsForDateAndTask(accountsByDateAndTaskDTO);
            return Ok(accounts);
        }

        [Authorize]
        [HttpGet("{id}")]
        public ActionResult<AccountResponse> GetById(string id)
        {
            var account = _accountService.GetById(id);
            // users can get their own account and admins can get any account
            if (id != Account.Id && Account.Role != Role.Admin)
            {
                log.ErrorFormat("User Id:{0} First Name:{1} Last Name:{2} e-mail:{3} tried to get the info about \n " +
                    "Id:{4} First Name:{5} Last Name:{6} e-mail:{7}",
                    Account.Id,
                    Account.FirstName,
                    Account.LastName,
                    Account.Email,

                    id,
                    account.FirstName,
                    account.LastName,
                    account.Email
                    );

                return Unauthorized(new { message = "Unauthorized. Needs an Administrator's attention" });
            }

            return Ok(account);
        }

        [Authorize]
        [HttpGet("all-dates")]
        public ActionResult<ScheduleDateTimeResponse> GetAllDates()
        {
            var dates = _accountService.GetAllDates();
            return Ok(dates);
        }

        [HttpGet("teams-for-date/{date}")]
        public ActionResult<DateFunctionTeamResponse> GetTeamsByFunctionForDate(string date)
        {
            var users = _accountService.GetTeamsByFunctionForDate(date);
            return Ok(users);
        }

        [Authorize]
        [HttpPut("add-schedule/{id}")]
        public ActionResult<AccountResponse> AddSchedule(string id, UpdateScheduleRequest schedule)
        {
            try
            {
                // users can update their own account and admins can update any account
                if (id != Account.Id && Account.Role != Role.Admin)
                    return Unauthorized(new { message = "Unauthorized" });

                var account = _accountService.AddSchedule(id, schedule);
                return Ok(account);
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpPost("update-schedule/{id}")]
        public ActionResult<AccountResponse> UpdateSchedule(string id, UpdateScheduleRequest schedule)
        {
            // users can update their own account and admins can update any account
            if (id != Account.Id && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            var account = _accountService.UpdateSchedule(id, schedule);
            return Ok(account);
        }

        [Authorize]
        [HttpPost("delete-schedule/{id}")]
        public ActionResult<AccountResponse> DeleteSchedule(string id, UpdateScheduleRequest schedule)
        {
            // users can update their own account and admins can update any account
            if (id != Account.Id && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            var account = _accountService.DeleteSchedule(id, schedule);
            return Ok(account);
        }
        [Authorize]
        [HttpDelete("delete-all-schedules")]
        public ActionResult<IEnumerable<ScheduleDateTimeResponse>> DeleteAllSchedules()
        {
            try
            {
                var accounts = _accountService.DeleteAllSchedules();
                return Ok(accounts);
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpPut("add-function/{id}")]
        public ActionResult<AccountResponse> AddFunction(string id, UpdateUserFunctionRequest function)
        {
            // users can update their own account and admins can update any account
            if (id != Account.Id && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            var account = _accountService.AddFunction(id, function);
            return Ok(account);
        }

        [Authorize]
        [HttpPost("delete-function/{id}")]
        public ActionResult<AccountResponse> DeleteFunction(string id, UpdateUserFunctionRequest function)
        {
            // users can update their own account and admins can update any account
            if (id != Account.Id && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            var (account, message) = _accountService.DeleteFunction(id, function);
            if (account == null)
            {
                return BadRequest(message);
            }
            return Ok(account);
        }

        [Authorize]
        [HttpPost("move-schedule-to-pool/{id}")]
        public ActionResult<AccountResponse> MoveSchedule2Pool(string id, UpdateScheduleRequest scheduleReq)
        {
            // users can update their own account and admins can update any account
            if (id != Account.Id && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            var pool = _accountService.MoveSchedule2Pool(id, scheduleReq);
            return Ok(pool);
        }

        [Authorize]
        [HttpPost("get-schedule-from-pool/{id}")]
        public ActionResult<AccountResponse> GetScheduleFromPool(string id, UpdateScheduleRequest scheduleReq)
        {
            // users can update their own account and admins can update any account
            if (id != Account.Id && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            var account = _accountService.GetScheduleFromPool(id, scheduleReq);
            if (account == null)
            {
                return NotFound();
            }

            return Ok(account);
        }

        [Authorize]
        [HttpPost("remove-pool-element/{id}/{email}/{userFunction}")]
        public ActionResult<SchedulePoolElementsResponse> RemovePoolElement(int id, string email, string userFunction)
        {
            var dates = _accountService.RemoveFromPool(id, email, userFunction);
            return Ok(dates);
        }

        [Authorize]
        [HttpGet("available_pool-elements-for-account/{id}")]
        public ActionResult<SchedulePoolElementsResponse> GetAvailablePoolElementsForAccount(string id)
        {
            var dates = _accountService.GetAvailablePoolElementsForAccount(id);
            return Ok(dates);
        }

        [Authorize]
        [HttpGet("all-available-pool-elements")]
        public ActionResult<SchedulePoolElementsResponse> GetAllAvailablePoolElements()
        {
            var dates = _accountService.GetAllAvailablePoolElements();
            return Ok(dates);
        }


        [Authorize]
        [HttpDelete("{id}")]
        public IActionResult Delete(string id)
        {
            // users can delete their own account and admins can delete any account
            if (id != Account.Id && Account.Role != Role.Admin)
                return Unauthorized(new { message = "Unauthorized" });

            _accountService.Delete(id);
            return Ok(new { message = "Account deleted successfully" });
        }

        [Authorize]
        [HttpGet("tasks")]
        public ActionResult<TaskResponse> GetTasks()
        {
            return Ok(_accountService.GetTasks());
        }

        [Authorize]
        [HttpGet("group-tasks")]
        public ActionResult<string[]> GetGroupTasks()
        {
            return Ok(_accountService.GetGroupTasks());
        }

        [Authorize]
        [HttpGet("all-tasks")]
        public ActionResult<string[]> GetAllTasks()
        {
            return Ok(_accountService.GetAllTasks());
        }

        [Authorize]
        [HttpGet("get-all-agent-task-configs")]
        public ActionResult<List<AgentTaskConfig>> GetAllAgentTaskConfigs()
        {
            try
            {
                return _accountService.GetAllAgentTaskConfigs();
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpPut("create-agent-task-config/{id}")]
        public ActionResult<AgentTaskConfig> UpdateAgentTaskConfig(string id, UpdateAgentTaskConfigRequest agentTaskConfigReq)
        {
            try
            {
                var result = _accountService.UpdateAgentTaskConfig(id, agentTaskConfigReq);
                return Ok(result);
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpDelete("delete-agent-task-config/{id}")]
        public IActionResult DeleteAgentTaskConfig(string id)
        {
            try
            {
                _accountService.DeleteAgentTaskConfig(id);
                return Ok();
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [Authorize]
        [HttpDelete("delete-all-agent-task-configs")]
        public IActionResult DeleteAllAgentTaskConfigs()
        {
            try
            {
                _accountService.DeleteAllAgentTaskConfigs();
                return Ok();
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpPost("upload-accounts"), DisableRequestSizeLimit]
        public ActionResult UploadAccounts()
        {
            try
            {
                var file = Request.Form.Files[0];
                string folderName = "Upload";
                string contentRootPath = _hostingEnvironment.ContentRootPath;
                string newPath = Path.Combine(contentRootPath, folderName);
                if (!Directory.Exists(newPath))
                {
                    Directory.CreateDirectory(newPath);
                }
                string fileName = "";
                if (file.Length > 0)
                {
                    fileName = ContentDispositionHeaderValue.Parse(file.ContentDisposition).FileName.Trim('"');
                    string fullPath = Path.Combine(newPath, fileName);
                    System.IO.File.Delete(fullPath);
                    using (var stream = new FileStream(fullPath, FileMode.Create))
                    {
                        file.CopyTo(stream);
                    }
                    _accountService.UploadAccounts(fullPath);
                }
                return Ok();
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpPost("upload-timeslots"), DisableRequestSizeLimit]
        public ActionResult UploadTimeSlots()
        {
            try
            {
                var file = Request.Form.Files[0];
                string folderName = "Upload";
                string contentRootPath = _hostingEnvironment.ContentRootPath;
                string newPath = Path.Combine(contentRootPath, folderName);
                if (!Directory.Exists(newPath))
                {
                    Directory.CreateDirectory(newPath);
                }
                string fileName = "";
                if (file.Length > 0)
                {
                    fileName = ContentDispositionHeaderValue.Parse(file.ContentDisposition).FileName.Trim('"');
                    string fullPath = Path.Combine(newPath, fileName);
                    System.IO.File.Delete(fullPath);
                    using (var stream = new FileStream(fullPath, FileMode.Create))
                    {
                        file.CopyTo(stream);
                    }
                    _accountService.ImportTimeSlotsTasks(fullPath);
                }
                return Ok();
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpGet("timeslots-tasks"), DisableRequestSizeLimit]
        public ActionResult<List<TimeSlotTasks>> GetTimeSlotsTasks()
        {
            try
            {

                var retVal = _accountService.GetTimeSlotsTasks();
                return Ok(retVal);
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpPut("timeslots-tasks")]
        public ActionResult<Boolean> SetTimeSlotsTasks(TimeSlotTasks tasks)
        {
            try
            {

                var retVal = _accountService.SetTimeSlotsTasks(tasks);
                return Ok(retVal);
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpPost("timeslots-tasks")]
        public ActionResult<Boolean> DeleteTimeSlotsTasks(TimeSlotTasks tasks)
        {
            try
            {

                var retVal = _accountService.DeleteTimeSlotsTasks(tasks);
                return Ok(retVal);
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpPost("generate-schedules")]
        public ActionResult<Boolean> GenerateSchedules()
        {
            try
            {
                var retVal = _accountService.GenerateSchedules();
                return Ok(retVal);
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpGet("download-schedules-file"), DisableRequestSizeLimit]
        public ActionResult DownloadSchedules()
        {
            try
            {
                Byte[] bytes = _accountService.DownloadSchedules();
                return File(bytes, "application/pdf");
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpDelete("delete-all-user-accounts")]
        public ActionResult<IEnumerable<AccountResponse>> DeleteAllUserAccounts()
        {
            try
            {
                var accounts = _accountService.DeleteAllUserAccounts();
                return Ok(accounts);
            }
            catch (System.Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
        [Authorize]
        [HttpGet("auto-email")]
        public ActionResult<Boolean> GetAutoEmail()
        {
            return Ok(_accountService.GetAutoEmail());
        }

        [Authorize]
        [HttpPut("auto-email")]
        public ActionResult<Boolean> SetAutoEmail([FromBody] Boolean autoEmail)
        {
            return Ok(_accountService.SetAutoEmail(autoEmail));
        }

        // helper methods

        private void setTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7),
                Secure = true,
                SameSite = SameSiteMode.None

            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}
