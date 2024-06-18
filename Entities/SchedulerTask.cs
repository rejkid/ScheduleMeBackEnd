using System;
using System.Collections.Generic;

namespace WebApi.Entities
{
    public class SchedulerTask
    {
        public int FunctionId { get; set; }
        public string UserFunction { get; set; }
        public string Group { get; set; }
        public Boolean IsGroup { get; set; } = false;
    }
}