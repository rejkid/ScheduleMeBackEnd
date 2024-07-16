using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using static iText.StyledXmlParser.Jsoup.Select.Evaluator;

namespace WebApi.Entities
{
    public class AgentTask : IEquatable<AgentTask>, IComparable<AgentTask>
    {
        [DefaultValue("1")]
        [Key]
        public int FunctionId { get; set; }
        public string PreferredTime { get; set; }
        public string UserFunction { get; set; }
        public string Group { get; set; }
        public Boolean IsGroup { get; set; } = false;

        public int CompareTo(AgentTask other)
        {
            if (UserFunction.CompareTo(other) != 0)
            {
                return UserFunction.CompareTo(other);
            }
            else
            { 
                return Group.CompareTo(other); 
            } 
        }

        public override bool Equals(object obj)
        {
            var newObj = obj as AgentTask;

            if (null != newObj)
            {
                return Equals(newObj);
            }
            else
            {
                return base.Equals(obj);
            }
        }

        public bool Equals(AgentTask other)
        {
            if (null != other)
            {
                return this.UserFunction == other.UserFunction
                    //&& this.PreferredTime == newObj.PreferredTime
                    && this.Group == other.Group
                    && this.GetHashCode() == other.GetHashCode();
            }
            else
            {
                return base.Equals(other);
            }
        }

        public override int GetHashCode()
        {
            int hash = 19;
            unchecked
            { // allow "wrap around" in the int
                hash = hash * 31 + this.UserFunction.GetHashCode();
                //hash = hash * 31 + this.PreferredTime.GetHashCode(); // assuming integer
                hash = hash * 31 + this.Group.GetHashCode();
            }
            return hash;
        }

        public override string ToString()
        {
            return base.ToString();
        }
    }
}