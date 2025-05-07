
using System;
using System.Collections.Generic;

namespace Sectra.UrlLaunch.UrlAccessString;

public static class UrlAccessStringTestsData {

    public static readonly Dictionary<string, Parameters> TestLaunchDictionary = new() {
        { "", new Parameters { AllowPatientChange = true, LimitedAccess = false, AutoselectLastAssignment = false } }, // Default parameters will be result in empty launch string.
        { "user_id=username", new Parameters { UserId = "username"} },
        { "pat_id=patient", new Parameters { PatientId = "patient"} },
        { "mrn_integration_id=DefaultMrnIntId", new Parameters { MrnIntegrationId = "DefaultMrnIntId"} },
        { "acc_no_integration_id=DefaultAccIntId", new Parameters { AccessionNumberGroup = "DefaultAccIntId" } },
        { "acc_no=req1^req2", new Parameters { AccessionNumber = new List<string>{"req1", "req2" } } },
        { "exam_id=ex1^ex2", new Parameters { ExaminationId = new List<string>{ "ex1", "ex2" } } },
        { "sop_uid=1.2.3", new Parameters { SopInstanceUid = "1.2.3" } },
        { "frame_number=123", new Parameters { OneBasedFrameNumber = 123 } },
        { "stop=1", new Parameters { Stop = true } },
        { "allow_pat_change=0", new Parameters { AllowPatientChange = false } },
        { "limited_access=1", new Parameters { LimitedAccess = true } },
        { "close_popup=1", new Parameters { ClosePopup = true } },
        { "init=1", new Parameters { Initialize = true } },
        { "login_type=url", new Parameters { LoginType = Parameters.LoginTypeEnum.Url} },
        { "login_type=sso", new Parameters { LoginType = Parameters.LoginTypeEnum.Sso} },
        { "sp=a2a6d41d-3ab3-47ec-802c-bf8aab26c977^5159555f-7982-4a95-a3a9-0c67b0e794b8^AccGroup%2cReq1%2cEx1", new Parameters { StartupPresentation = new StartupPresentationData(new Guid("A2A6D41D-3AB3-47EC-802C-BF8AAB26C977"), new Guid("5159555F-7982-4A95-A3A9-0C67B0E794B8"), "AccGroup,Req1,Ex1")} },
        { "sp=null^null^AccGroup%2cReq1%2cEx1", new Parameters { StartupPresentation = new StartupPresentationData(Guid.Empty, Guid.Empty, "AccGroup,Req1,Ex1")} },
        { "pat_name=name", new Parameters { PatientName = "name"} },
        { "pat_birth=19600515", new Parameters { PatientBirthdate = new DateTime(1960, 5, 15)} },
        { "pat_sex=M", new Parameters { PatientSex = "M"} },
        { "ref_unit=unit", new Parameters { ReferringUnit = "unit"} },
        { "his_id=hisid", new Parameters { HisId = "hisid"} },
        { "uniview_cmd=show_images", new Parameters { UniViewCommand = Parameters.UniViewCommandEnum.ShowImages } },
        { "uv_layout=image_and_toolbar", new Parameters { UniViewLayout = Parameters.UniViewLayoutEnum.ImageAndToolbar } },
        { "autoselect_last_assignment=1", new Parameters { AutoselectLastAssignment = true } },
        { "ids7_workspace=reporting", new Parameters { Ids7Workspace = "reporting" } },
        { "ids7_workspace=classic", new Parameters { Ids7Workspace = "classic" } },
        { "ids7_workspace=touch", new Parameters { Ids7Workspace = "touch" } },
        { "ids7_cmds=open_ipv_window", new Parameters { Ids7Commands = new List<string>{ "open_ipv_window" } } },
        { "use_search_servers_from_worklist=WL_ID1", new Parameters {UseSearchServersFromWorklist = "WL_ID1" } },
        { "promote_server_to_query=Server1", new Parameters {PromoteServerToQuery = "Server1" } },
        { "ids7_window_management=image_window", new Parameters { Ids7WindowManagement = Parameters.Ids7WindowManagementEnum.ImageWindow } },
        { "ids7_window_management=information_window", new Parameters { Ids7WindowManagement = Parameters.Ids7WindowManagementEnum.InformationWindow } },
        { "ids7_window_management=keep_in_background", new Parameters { Ids7WindowManagement = Parameters.Ids7WindowManagementEnum.KeepInBackground } }
    };

    public static readonly Dictionary<string, Parameters> TestParseDictionary = new() {
        { "user_id=username", new Parameters { UserId = "username"} },
        { "pat_id=patient", new Parameters { PatientId = "patient"} },
        { "mrn_integration_id=DefaultMrnIntId", new Parameters { MrnIntegrationId = "DefaultMrnIntId"} },
        { "acc_no_integration_id=DefaultAccIntId", new Parameters { AccessionNumberGroup = "DefaultAccIntId" } },
        { "acc_no=req1^req2", new Parameters { AccessionNumber = new List<string>{"req1", "req2" } } },
        { "exam_id=ex1^ex2", new Parameters { ExaminationId = new List<string>{ "ex1", "ex2" } } },
        { "sop_uid=1.2.3", new Parameters { SopInstanceUid = "1.2.3" } },
        { "frame_number=123", new Parameters { OneBasedFrameNumber = 123 } },
        { "stop=1", new Parameters { Stop = true } },
        { "allow_pat_change=0", new Parameters { AllowPatientChange = false } },
        { "limited_access=1", new Parameters { LimitedAccess = true, AllowPatientChange = false } },
        { "init=1", new Parameters { Initialize = true } },
        { "login_type=url", new Parameters { LoginType = Parameters.LoginTypeEnum.Url} },
        { "login_type=sso", new Parameters { LoginType = Parameters.LoginTypeEnum.Sso} },
        { "sp=a2a6d41d-3ab3-47ec-802c-bf8aab26c977^5159555f-7982-4a95-a3a9-0c67b0e794b8^AccGroup%2cReq1%2cEx1", new Parameters { StartupPresentation = new StartupPresentationData(new Guid("A2A6D41D-3AB3-47EC-802C-BF8AAB26C977"), new Guid("5159555F-7982-4A95-A3A9-0C67B0E794B8"), "AccGroup,Req1,Ex1")} },
        { "sp=null^null^AccGroup%2cReq1%2cEx1", new Parameters { StartupPresentation = new StartupPresentationData(Guid.Empty, Guid.Empty, "AccGroup,Req1,Ex1")} },
        { "pat_name=name", new Parameters { PatientName = "name"} },
        { "pat_birth=19600515", new Parameters { PatientBirthdate = new DateTime(1960, 5, 15)} },
        { "pat_sex=F", new Parameters { PatientSex = "F"} },
        { "ref_unit=unit", new Parameters { ReferringUnit = "unit"} },
        { "his_id=hisid", new Parameters { HisId = "hisid"} },
        { "uniview_cmd=show_images", new Parameters { UniViewCommand = Parameters.UniViewCommandEnum.ShowImages } },
        { "uv_layout=image_and_toolbar", new Parameters { UniViewLayout = Parameters.UniViewLayoutEnum.ImageAndToolbar } },
        { "autoselect_last_assignment=1", new Parameters { AutoselectLastAssignment = true } },
        { "ids7_workspace=reporting", new Parameters { Ids7Workspace = "reporting" } },
        { "ids7_workspace=classic", new Parameters { Ids7Workspace = "classic" } },
        { "ids7_workspace=touch", new Parameters { Ids7Workspace = "touch" } },
        { "ids7_cmds=open_ipv_window", new Parameters { Ids7Commands = new List<string>{ "open_ipv_window" } } },
        { "use_search_servers_from_worklist=WL_ID1", new Parameters {UseSearchServersFromWorklist = "WL_ID1" } },
        { "promote_server_to_query=Server1", new Parameters {PromoteServerToQuery = "Server1" } },
        { "ids7_window_management=image_window", new Parameters { Ids7WindowManagement = Parameters.Ids7WindowManagementEnum.ImageWindow } },
        { "ids7_window_management=information_window", new Parameters { Ids7WindowManagement = Parameters.Ids7WindowManagementEnum.InformationWindow } },
        { "ids7_window_management=keep_in_background", new Parameters { Ids7WindowManagement = Parameters.Ids7WindowManagementEnum.KeepInBackground } }
    };
}
