using System;
using System.Collections.Generic;
using System.Web;
using static Sectra.UrlLaunch.UrlAccessString.QueryStringUtility;

namespace Sectra.UrlLaunch.UrlAccessString;

public static class QueryString {

    /// <summary>
    /// Returns the url query string given some <see cref="parameters"/>.
    /// </summary>
    public static string GetQueryString(Parameters parameters) {
        return GetQueryString(parameters, parameters.Time);
    }

    /// <summary>
    /// Returns the url query string given some <see cref="parameters"/> using current time.
    /// </summary>
    /// <remarks>This will ignore the Time parameter from the Parameters object</remarks>
    public static string GetQueryStringWithCurrentTime(Parameters parameters) {
        return GetQueryString(parameters, DateTime.UtcNow);
    }

    /// <summary>
    /// Returns the url query string given some <see cref="parameters"/>.
    /// </summary>
    private static string GetQueryString(Parameters parameters, DateTime? time) {
        var queryParameters = new List<string>();
        if (parameters.PatientId != null && !string.IsNullOrEmpty(parameters.PatientId)) {
            queryParameters.Add(CreateUrlParameter("pat_id", parameters.PatientId));
        }

        if (parameters.AccessionNumber != null && parameters.AccessionNumber.Count > 0) {
            string accessionNumbers = ListToString(parameters.AccessionNumber);
            queryParameters.Add(CreateUrlParameter("acc_no", accessionNumbers, false));
        }

        if (parameters.ExaminationId != null && parameters.ExaminationId.Count > 0) {
            string examinationIds = ListToString(parameters.ExaminationId);
            queryParameters.Add(CreateUrlParameter("exam_id", examinationIds, false));
        }

        if (parameters.MrnIntegrationId != null && !string.IsNullOrEmpty(parameters.MrnIntegrationId)) {
            queryParameters.Add(CreateUrlParameter("mrn_integration_id", parameters.MrnIntegrationId));
        }

        if (parameters.AccessionNumberGroup != null && !string.IsNullOrEmpty(parameters.AccessionNumberGroup)) {
            queryParameters.Add(CreateUrlParameter("acc_no_integration_id", parameters.AccessionNumberGroup));
        }

        if (parameters.ApplicationId != null && !string.IsNullOrEmpty(parameters.ApplicationId)) {
            queryParameters.Add(CreateUrlParameter("application_id", parameters.ApplicationId));
        }

        if (parameters.AssignmentId != null && !string.IsNullOrEmpty(parameters.AssignmentId)) {
            queryParameters.Add(CreateUrlParameter("assignment_id", parameters.AssignmentId));
        }

        if (parameters.CareUnitIdIssuer != null && !string.IsNullOrEmpty(parameters.CareUnitIdIssuer)) {
            queryParameters.Add(CreateUrlParameter("care_unit_id_issuer", parameters.CareUnitIdIssuer));
        }

        if (parameters.CareUnitId != null && !string.IsNullOrEmpty(parameters.CareUnitId)) {
            queryParameters.Add(CreateUrlParameter("care_unit_id", parameters.CareUnitId));
        }

        if (parameters.UserId != null && !string.IsNullOrEmpty(parameters.UserId)) {
            queryParameters.Add(CreateUrlParameter("user_id", parameters.UserId));
        }

        if (parameters.Stop.HasValue && parameters.Stop.Value) {
            queryParameters.Add(CreateUrlParameter("stop", "1"));
        }

        if (parameters.SopInstanceUid != null && !string.IsNullOrEmpty(parameters.SopInstanceUid)) {
            queryParameters.Add(CreateUrlParameter("sop_uid", parameters.SopInstanceUid));
        }

        if (parameters.OneBasedFrameNumber.HasValue) {
            queryParameters.Add(CreateUrlParameter("frame_number", parameters.OneBasedFrameNumber.Value.ToString()));
        }

        if (parameters.UniViewCommand.HasValue && parameters.UniViewCommand != Parameters.UniViewCommandEnum.None) {
            queryParameters.Add(CreateUrlParameter("uniview_cmd", CreateUniViewCmd(parameters.UniViewCommand.Value)));
        }

        if (parameters.Ids7Commands != null && parameters.Ids7Commands.Count > 0) {
            string cmds = ListToString(parameters.Ids7Commands);
            queryParameters.Add(CreateUrlParameter("ids7_cmds", cmds, false));
        } else if (parameters.Ids7Command.HasValue && parameters.Ids7Command != Parameters.Ids7CommandEnum.None) {
            queryParameters.Add(CreateUrlParameter("ids7_cmds", CreateIds7Command(parameters.Ids7Command.Value), false));
        }

        if (parameters.UniViewLayout.HasValue && parameters.UniViewLayout != Parameters.UniViewLayoutEnum.Default) {
            queryParameters.Add(CreateUrlParameter("uv_layout", CreateUniViewLayout(parameters.UniViewLayout.Value)));
        }

        if (parameters.PathologyCommand != null && !string.IsNullOrEmpty(parameters.PathologyCommand)) {
            queryParameters.Add(CreateUrlParameter("pathology_cmd", parameters.PathologyCommand));
        }

        if (parameters.AllowPatientChange.HasValue && !parameters.AllowPatientChange.Value) {
            queryParameters.Add(CreateUrlParameter("allow_pat_change", "0"));
        }

        if (parameters.PromoteExtendedPatientSearchServers.HasValue && parameters.PromoteExtendedPatientSearchServers.Value) {
            queryParameters.Add(CreateUrlParameter("promote_extended_patient_search_servers", "1"));
        }

        if (parameters.LimitedAccess.HasValue && parameters.LimitedAccess.Value) {
            queryParameters.Add(CreateUrlParameter("limited_access", "1"));
        }

        if (parameters.AutoselectLastAssignment.HasValue && parameters.AutoselectLastAssignment.Value) {
            queryParameters.Add(CreateUrlParameter("autoselect_last_assignment", "1"));
        }

        if (parameters.LoginType.HasValue) {
            var stringLoginType = parameters.LoginType.ToString() ?? string.Empty;
            queryParameters.Add(CreateUrlParameter("login_type", stringLoginType.ToLower()));
        }

        if (parameters.StartupPresentation != null) {
            var startupPresentationArgs = new List<string> {
                parameters.StartupPresentation.DisplayUnitGuid == Guid.Empty ? StartupPresentationData.EmptyGuidString : parameters.StartupPresentation.DisplayUnitGuid.ToString(),
                parameters.StartupPresentation.DatabaseGuid == Guid.Empty ? StartupPresentationData.EmptyGuidString : parameters.StartupPresentation.DatabaseGuid.ToString(),
                parameters.StartupPresentation.BaseRpCookie };

            string escapedStr = ListToString(startupPresentationArgs, "^", true);
            queryParameters.Add("sp=" + escapedStr);
        }

        if (parameters.PatientName != null && !string.IsNullOrEmpty(parameters.PatientName)) {
            string escapedStr = EscapeString(parameters.PatientName);
            queryParameters.Add("pat_name=" + escapedStr);
        }

        if (parameters.PatientBirthdate != null) {
            string escapedStr = EscapeString(parameters.PatientBirthdate.Value.ToString("yyyyMMdd"));
            queryParameters.Add("pat_birth=" + escapedStr);
        }

        if (parameters.PatientSex != null && !string.IsNullOrEmpty(parameters.PatientSex)) {
            string escapedStr = EscapeString(parameters.PatientSex);
            queryParameters.Add("pat_sex=" + escapedStr);
        }

        if (parameters.ReferringUnit != null && !string.IsNullOrEmpty(parameters.ReferringUnit)) {
            string escapedStr = EscapeString(parameters.ReferringUnit);
            queryParameters.Add("ref_unit=" + escapedStr);
        }

        if (parameters.HisId != null && !string.IsNullOrEmpty(parameters.HisId)) {
            string escapedStr = EscapeString(parameters.HisId);
            queryParameters.Add("his_id=" + escapedStr);
        }

        if (parameters.Initialize.HasValue && parameters.Initialize.Value) {
            queryParameters.Add(CreateUrlParameter("init", "1"));
        }

        if (parameters.Ids7WindowManagement.HasValue) {
            queryParameters.Add(CreateUrlParameter("ids7_window_management", CreateIds7WindowManagement(parameters.Ids7WindowManagement.Value)));
        }

        if (parameters.Ids7Workspace != null && !string.IsNullOrEmpty(parameters.Ids7Workspace)) {
            queryParameters.Add(CreateUrlParameter("ids7_workspace", parameters.Ids7Workspace));
        }

        if (parameters.NdBookmark != null && !string.IsNullOrEmpty(parameters.NdBookmark)) {
            queryParameters.Add(CreateUrlParameter("nd_bookmark", parameters.NdBookmark));
        }

        if (parameters.UseSearchServersFromWorklist != null && !string.IsNullOrEmpty(parameters.UseSearchServersFromWorklist)) {
            queryParameters.Add(CreateUrlParameter("use_search_servers_from_worklist", parameters.UseSearchServersFromWorklist));
        }

        if (parameters.PromoteServerToQuery != null && !string.IsNullOrEmpty(parameters.PromoteServerToQuery)) {
            queryParameters.Add(CreateUrlParameter("promote_server_to_query", parameters.PromoteServerToQuery));
        }

        if (time.HasValue) {
            // Add time
            var timestamp = TimeToSeconds(time.Value).ToString();
            queryParameters.Add(CreateUrlParameter("time", timestamp));
        }

        // The close_popup parameter shouldn't be included in the hash.
        if (parameters.ClosePopup.HasValue && parameters.ClosePopup.Value) {
            queryParameters.Add(CreateUrlParameter("close_popup", "1"));
        }

        return string.Join("&", queryParameters);
    }

    /// <summary>
    /// Parse the legacy encoded query string
    /// </summary>
    public static Parameters Parse(string queryString, Action<Parameters>? validateParameters = null) {
        return InternalParseAccessStringEncodingWrapper(queryString, validateParameters);
    }

    /// <summary>
    /// Parse the legacy encoded query string
    /// </summary>
    private static Parameters InternalParseAccessStringEncodingWrapper(string queryString, Action<Parameters>? validateParameters) {
        try {
            return InternalParseAccessString(queryString, validateParameters);
        }
        catch (ArgumentException) {
            // This is a fix for making url-launch using WorkstationStarter/MSI work on Windows 8.
            // On Win7 and earlier "protocol"-arguments like "ids7:" and "ids7agent:" was implicitly
            // decoded whereas on Win8 they are not, i.e. if you try to launch IDS7 using the
            // url "ids7agent:a%3db" the argument "a=b" will be passed to the corresponding process
            // on Win7 and earlier, but "a%3db" will be passed on Win8.
            string decodedString = HttpUtility.UrlDecode(queryString);

            return InternalParseAccessString(decodedString, validateParameters);
        }
    }

    /// <summary>
    /// Parses the access string.
    /// </summary>
    private static Parameters InternalParseAccessString(string accessString, Action<Parameters>? validateParameters) {
        var parameters = new Parameters();
        if (accessString.Length != 0) {

            // Parameters that should be ignored
            var ignoredParams = new HashSet<string> { "key", "close_popup", "client" };

            // Parse the access string
            string[] args = accessString.Split('&');
            foreach (string arg in args) {
                string[] param = arg.Split('=');

                if (param.Length != 2) {
                    throw new ArgumentException("Invalid query syntax: " + accessString);
                }

                string paramName = param[0];
                string paramValue = param[1];

                if (ignoredParams.Contains(paramName)) {
                    continue;
                }

                // Parse each argument
                switch (paramName) {
                    case "user_id":
                        parameters.UserId = UnEscapeString(paramValue);
                        break;
                    case "time":
                        var time1970 = new DateTime(1970, 1, 1);
                        long secondsSince1970 = long.Parse(paramValue);
                        parameters.Time = time1970.AddSeconds(secondsSince1970);
                        break;
                    case "login_type":
                        parameters.LoginType = ParseEnum<Parameters.LoginTypeEnum>(paramValue);
                        break;
                    case "pat_id":
                        parameters.PatientId = UnEscapeString(paramValue);
                        break;
                    case "mrn_group": // For backward compatibility
                    case "pat_id_issuer":
                    case "mrn_integration_id":
                        parameters.MrnIntegrationId = UnEscapeString(paramValue);
                        break;
                    case "acc_no":
                        parameters.AccessionNumber = ParseList(paramValue, true);
                        break;
                    case "acc_no_group": // For backward compability
                    case "acc_no_integration_id":
                        parameters.AccessionNumberGroup = UnEscapeString(paramValue);
                        break;
                    case "exam_id":
                        parameters.ExaminationId = ParseList(paramValue, true);
                        break;
                    case "sop_uid":
                        parameters.SopInstanceUid = UnEscapeString(paramValue);
                        break;
                    case "frame_number":
                        if (int.TryParse(paramValue, out int frameNumber) && (frameNumber >= 1)) {
                            parameters.OneBasedFrameNumber = frameNumber;
                        } else {
                            throw new ArgumentException($"Invalid syntax. Parameter: {paramName} Value: {paramValue}");
                        }

                        break;
                    case "sp":
                        // Arguments used by the thumbnail control to create
                        // a startup presentation that displays the thumbnail series.

                        // Syntax for args is: <display unit guid>^<datbase guid>^<base rp cookie>
                        List<string> dpArgs = ParseList(paramValue, true);
                        if (dpArgs.Count != 3) {
                            throw new ArgumentException(
                                $"Invalid syntax. Parameter: {paramName} Value: {paramValue}");
                        }

                        // Create container for startup presentation arguments
                        parameters.StartupPresentation = new StartupPresentationData(
                            dpArgs[0] == StartupPresentationData.EmptyGuidString ? Guid.Empty : new Guid(dpArgs[0]),
                            dpArgs[1] == StartupPresentationData.EmptyGuidString ? Guid.Empty : new Guid(dpArgs[1]),
                            dpArgs[2]);
                        break;
                    case "stop":
                        if (paramValue != "0") {
                            parameters.Stop = true;
                        }

                        break;
                    case "init":
                        if (paramValue != "0") {
                            parameters.Initialize = true;
                        }

                        break;
                    case "pat_name":
                        string patientName = UnEscapeString(paramValue);
                        if (!IsPersonName(patientName)) {
                            throw new ArgumentException(
                                $"'{patientName}' is not a valid DICOM person name (family name complex^given name complex^middle name^name prefix^name suffix)");
                        }

                        parameters.PatientName = patientName;
                        break;
                    case "pat_birth":
                        string birthdate = UnEscapeString(paramValue);
                        if (!IsDate(birthdate, out string parsedDate)) {
                            throw new ArgumentException(
                                $"'{birthdate}' is not a valid DICOM date (YYYYMMDD)");
                        }

                        parameters.PatientBirthdate = DateTime.ParseExact(UnEscapeString(parsedDate), "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture);
                        break;
                    case "pat_sex":
                        string sex = UnEscapeString(paramValue);
                        if (!IsPatientSex(sex, out string? parsedSex)) {
                            throw new ArgumentException(
                                $"'{sex}' is not a valid DICOM sex (EMPTY, M, F or O)");
                        }

                        parameters.PatientSex = parsedSex;
                        break;
                    case "ref_unit":
                        string refUnit = UnEscapeString(paramValue);
                        if (!IsLongString(refUnit)) {
                            throw new ArgumentException(
                                $"'{refUnit}' is not a DICOM long string.");
                        }

                        parameters.ReferringUnit = refUnit;
                        break;
                    case "his_id":
                        parameters.HisId = UnEscapeString(paramValue);
                        break;
                    case "cmd":
                        parameters.OmCmd = ParseOMCmd(paramValue);
                        break;
                    case "uniview_cmd":
                        parameters.UniViewCommand = ParseUniViewCmd(paramValue);
                        break;
                    case "ids7_cmds":
                        parameters.Ids7Commands = ParseList(paramValue, true);
                        break;
                    case "ids7_window_management":
                        parameters.Ids7WindowManagement = ParseIds7WindowManagement(paramValue);
                        break;
                    case "ids7_workspace":
                        parameters.Ids7Workspace = UnEscapeString(paramValue);
                        break;
                    case "nd_bookmark":
                        parameters.NdBookmark = UnEscapeString(paramValue);
                        break;
                    case "uv_layout":
                        parameters.UniViewLayout = ParseUniViewLayout(paramValue);
                        break;
                    case "pathology_cmd":
                        parameters.PathologyCommand = UnEscapeString(paramValue);
                        break;
                    case "allow_pat_change":
                        parameters.AllowPatientChange = paramValue != "0";
                        break;
                    case "limited_access":
                        parameters.LimitedAccess = paramValue != "0";
                        break;
                    case "autoselect_last_assignment":
                        parameters.AutoselectLastAssignment = paramValue != "0";
                        break;
                    case "assignment_id":
                        parameters.AssignmentId = UnEscapeString(paramValue);
                        break;
                    case "care_provider_id":
                    case "care_unit_id_issuer":
                        parameters.CareUnitIdIssuer = UnEscapeString(paramValue);
                        break;
                    case "care_unit_id":
                        parameters.CareUnitId = UnEscapeString(paramValue);
                        break;
                    case "application_id":
                        parameters.ApplicationId = UnEscapeString(paramValue);
                        break;
                    case "use_search_servers_from_worklist":
                        parameters.UseSearchServersFromWorklist = UnEscapeString(paramValue);
                        break;
                    case "promote_extended_patient_search_servers":
                        parameters.PromoteExtendedPatientSearchServers = paramValue != "0";
                        break;
                    case "promote_server_to_query":
                        parameters.PromoteServerToQuery = UnEscapeString(paramValue);
                        break;
                    default:
                        throw new ArgumentException("Unknown parameter: " + paramName);
                }
            }
        }

        if (parameters.LimitedAccess.HasValue && parameters.LimitedAccess.Value) {
            // Implicitly implies that patient change is also restricted.
            parameters.AllowPatientChange = false;
        }

        validateParameters?.Invoke(parameters);

        return parameters;
    }

    /// <summary>
    /// Example validation logic
    /// </summary>
    /// <remarks>The actual validation is depending on product, release and configuration. This is added as a default example.</remarks>
    public static void Validate(Parameters parameters) {
        // If the stop command is set nothing matters, logoff will be performed
        if (parameters.Stop.HasValue && parameters.Stop.Value) {
            return;
        }

        if (parameters.PatientId == null && parameters.AccessionNumber?.Count > 0) {
            throw new ArgumentException("A patient ID must be given if any examination IDs or accession numbers are given.");
        }

        var examinationId = parameters.ExaminationId ?? new List<string>();
        var accessionNumber = parameters.AccessionNumber ?? new List<string>();
        if ((parameters.SopInstanceUid != null) && ((examinationId.Count != 1) || (accessionNumber.Count != 1))) {
            throw new ArgumentException("One single accession number and examination ID must be specified in combination with SOP Instance UID.");
        }

        if (examinationId.Count > 0 && examinationId.Count != accessionNumber.Count) {
            if (examinationId.Count > 0 && accessionNumber.Count > 0 && examinationId.Count != accessionNumber.Count) {
                throw new ArgumentException("The examination identifiers should be given in pairs with accession numbers.");
            }
        }

        // Order management validation
        switch (parameters.OmCmd) {
            case Parameters.OrderManagementCommandEnum.None:
                break;
            case Parameters.OrderManagementCommandEnum.CreateRequest:
                if (string.IsNullOrEmpty(parameters.PatientId)) {
                    throw new ArgumentException("The pat_id parameter is required for a Create request external launch.");
                }

                break;
            case Parameters.OrderManagementCommandEnum.ScheduleRequestExaminations:
                if (parameters.AccessionNumber == null || parameters.AccessionNumber.Count == 0) {
                    throw new ArgumentException("An internal or external accession number must be supplied when scheduling a request.");
                }

                break;
            case Parameters.OrderManagementCommandEnum.OpenReferringUnitOverview:
                if (string.IsNullOrEmpty(parameters.ReferringUnit)) {
                    throw new ArgumentException("The ref_unit parameter is required for scheduler overview.");
                }

                break;
            case Parameters.OrderManagementCommandEnum.SearchPatient:
                if (string.IsNullOrEmpty(parameters.PatientId)) {
                    throw new ArgumentException("The pat_id parameter is required when searching for a patient.");
                }

                break;
        }

        switch (parameters.UniViewCommand) {
            case Parameters.UniViewCommandEnum.None:
                break;
            case Parameters.UniViewCommandEnum.ShowImages:
                if (string.IsNullOrEmpty(parameters.PatientId)) {
                    throw new ArgumentException("The pat_id parameter is required when showing images.");
                }
                break;
        }
    }
}
