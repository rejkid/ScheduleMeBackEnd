using AutoMapper;
using log4net;
using System;
using WebApi.Entities;
using WebApi.Models.Accounts;

namespace WebApi.Helpers
{
    public class AutoMapperProfile : Profile
    {
        private static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        // mappings between model and entity objects
        public AutoMapperProfile()
        {
            CreateMap<Account, User>();
            //.ForMember(dest => dest.Id, opt => opt.MapFrom(src => src.AccountId));


            //CreateMap<Schedule, SchedulePoolElement>()
            //    /*.ForMember(dest => dest.Id, opt => opt.MapFrom(src => src.ScheduleId))*/;

            // CreateMap<Schedule, SchedulePoolElement>();
            // CreateMap<SchedulePoolElement, Schedule>();

            CreateMap<Account, AccountResponse>();
            //.ForMember(dest => dest.Dob, opt => opt.MapFrom(src => src));

            CreateMap<Account, AuthenticateResponse>();
                //.ForMember(dest => dest.Id, opt => opt.MapFrom(src => src.AccountId));

            CreateMap<RegisterRequest, Account>()
                .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => src.Email));

            CreateMap<CreateRequest, Account>()
                .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => src.Email+ src.Dob.ToString().Replace('/', '_').Replace(':', '_').Replace(' ', '_')
                ));

            CreateMap<UpdateScheduleRequest, Schedule>();
            //.ForMember(dest => dest.Date, opt =>
            //{
            //    opt.MapFrom(src => DateTime.ParseExact(src.Date, ConstantsDefined.DateTimeFormat, System.Globalization.CultureInfo.InvariantCulture));
            //    log.Info("ForMember called");
            //});

            CreateMap<UpdateScheduleRequest, SchedulePoolElement>();


            CreateMap<UpdateUserFunctionRequest, Function>();
            //    .ForMember(dest => dest.UserFunction, opt => opt.MapFrom(src => src.Task.UserFunction))
            //    .ForMember(dest => dest.IsGroup, opt => opt.MapFrom(src => src.Task.IsGroup));


            CreateMap<AccountRequest, Account>()
            // .ForMember(d => d.Role, 
            //     op => op.MapFrom(o=> MapGrade(o.Role)))

            .ForMember(d => d.Schedules, op => op.Ignore())
            .ForMember(d => d.UserFunctions, op => op.Ignore())
            .ForAllMembers(x => x.Condition(
                (src, dest, propSrc, propDst, resolutionContext) =>
                {
                    // ignore null & empty string properties - with exception of PhoneNumber
                    if (propSrc == null && x.DestinationMember.Name != "PhoneNumber") return false;
                    if ((x.DestinationMember.Name != "PhoneNumber") && (propSrc.GetType() == typeof(string)) && string.IsNullOrEmpty((string)propSrc)) return false;

                    // ignore null role
                    if (x.DestinationMember.Name == "Role" && src.Role == null) return false;

                    return true;
                }
            ));

            //CreateMap<Account, UpdateRequest>();
        }
    }
   
}