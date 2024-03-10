using System;
using System.Diagnostics.CodeAnalysis;

namespace WebApi.Entities
{
    public class Schedule
    {
        public int ScheduleId { get; set; }
        public string Date { get; set; }
        public string Dob { get; set; }
        public Boolean Required { get; set; }
        public string Email { get; set; }
        public Boolean UserAvailability { get; set; }
        public string UserFunction { get; set; }
        // Notification section

        [NotNull]
        public string ScheduleGroup { get; set; } = "";
        public bool NotifiedWeekBefore { get; set; } = false;
        public bool NotifiedThreeDaysBefore { get; set; } = false;
        // End of Notification section

        /* Reward section*/
        public uint NoOfTimesAssigned { get; set; }
        public uint NoOfTimesDropped { get; set; }
    }
}