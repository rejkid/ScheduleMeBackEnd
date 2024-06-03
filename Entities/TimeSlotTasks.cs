using iText.Layout.Element;
using System;
using System.Collections.Generic;

namespace WebApi.Entities
{
    public class TimeSlotTasks
    {
        public int TimeSlotTasksId { get; set; }
        public string Date { get; set; }
        
        public string Tasks { get; set; }
    }
}
