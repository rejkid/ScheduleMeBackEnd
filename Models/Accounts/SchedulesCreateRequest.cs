
using System.Collections.Generic;
using WebApi.Entities;

namespace WebApi.Models.Accounts
{
    public class SchedulesCreateRequest
    {
        
        
        public UpdateScheduleRequest[] Schedules { get; set; }
    }
}