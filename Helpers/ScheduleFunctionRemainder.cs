using System.Threading;
using System;
using log4net;
using WebApi.Entities;
using Microsoft.EntityFrameworkCore;
using WebApi.Services;
using System.Linq;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;
using Google;
using System.Configuration;
using System.IO;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Generic;
using System.Security.Principal;
using Newtonsoft.Json.Linq;
using Microsoft.EntityFrameworkCore.Storage;

namespace WebApi.Helpers
{
    public class ScheduleFunctionRemainder// : IScheduleFunctionRemainderService
    {
        public static TimeSpan HOUR_TIMEOUT = new TimeSpan(0, /*1*/0, /*0*/1, 0);         // Hourly timeout

        private static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        private static bool terminate = false;
        private static DataContext _context;
        private static IEmailService _emailService;
        private static IAccountService _accountService;
        private readonly IServiceScope scope;
        private static IConfiguration _configuration;

        public ScheduleFunctionRemainder(IServiceProvider provider)
        {
            scope = provider.CreateScope();
            _context = scope.ServiceProvider.GetRequiredService<DataContext>();
            _emailService = scope.ServiceProvider.GetRequiredService<IEmailService>();
            _configuration = scope.ServiceProvider.GetRequiredService<IConfiguration>();
            _accountService = scope.ServiceProvider.GetRequiredService<IAccountService>(); ;
        }

        // This method is called by the timer delegate.
        public static void CheckStatus(/*Object stateInfo*/)
        {
            DateTime prevDate = DateTime.Now;

            Console.WriteLine("Checking status {0}.", DateTime.Now.ToString("h:mm:ss.fff"));

            do // Check if the caller requested cancellation. 
            {

                DateTime now = DateTime.Now;
                // Calculate the interval between the two dates.  
                TimeSpan ts = now - prevDate;

                if (ts.TotalMilliseconds > HOUR_TIMEOUT.TotalMilliseconds) // Send e-mail every hour
                {
                    prevDate = DateTime.Now;

                    if (_accountService.GetAutoEmail())
                    {
                        _accountService.SendRemindingEmail4Functions();
                    }
                }
                Thread.Sleep(500);
            } while (!terminate);

            if (terminate)
            {
                // Reset the counter and signal the waiting thread.
                _context.Dispose();
                log.InfoFormat("Timer reminding the function to attend has exited gracefully. {0} ", "");
            }
        }
        public void Terminate()
        {
            terminate = true;
        }
    }
}
