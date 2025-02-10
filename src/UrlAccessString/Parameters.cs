
using System;
using System.Collections.Generic;

namespace Sectra.UrlLaunch.UrlAccessString;

public record Parameters {
    /// <summary>
    /// Order Management commands
    /// </summary>
    public enum OrderManagementCommandEnum {
        None,
        CreateRequest,
        ScheduleRequestExaminations,
        OpenReferringUnitOverview,
        SearchPatient,
        OrderOverview
    }

    /// <summary>
    /// IDS7 commands
    /// </summary>
    public enum Ids7CommandEnum {
        None,
        OpenIpvWindow
    }

    /// <summary>
    /// IDS7 window management
    /// </summary>
    public enum Ids7WindowManagementEnum {
        ImageWindow,
        InformationWindow,
        KeepInBackground,
    }

    /// <summary>
    /// UniView commands
    /// </summary>
    public enum UniViewCommandEnum {
        None,
        ShowImages
    }

    /// <summary>
    /// Non-standard UniView layouts that affect element visibility and placement.
    /// </summary>
    public enum UniViewLayoutEnum {
        /// <summary> Standard layout </summary>
        Default,
        /// <summary>
        /// Hides most elements except the image view and the toolbar. Intended for embedding UniView in
        /// educational applications.
        /// </summary>
        ImageAndToolbar
    }

    /// <summary>
    /// Login type
    /// </summary>
    public enum LoginTypeEnum {
        Url,
        Sso,
    }

    /// <summary>
    /// Time
    /// </summary>
    public DateTime? Time { get; set; }

    /// <summary>
    /// Returns the login type (URL or SSO)
    /// </summary>
    public LoginTypeEnum? LoginType { get; set; }

    /// <summary>
    /// Specifies whether the application should be stopped or not.
    /// </summary>
    public bool? Stop { get; set; }

    /// <summary>
    /// Assignment Id.
    /// </summary>
    public string? AssignmentId { get; set; }

    /// <summary>
    /// Care Provider Id.
    /// </summary>
    public string? CareUnitIdIssuer { get; set; }

    /// <summary>
    /// Care unit Id.
    /// </summary>
    public string? CareUnitId { get; set; }

    /// <summary>
    /// User id.
    /// </summary>
    public string? UserId { get; set; }

    /// <summary>
    /// Patient ID.
    /// </summary>
    public string? PatientId { get; set; }

    /// <summary>
    /// Issuer of Patient ID.
    /// </summary>
    public string? MrnIntegrationId { get; set; }

    /// <summary>
    /// Accession number.
    /// </summary>
    public List<string>? AccessionNumber { get; set; }

    /// <summary>
    /// Accession number group.
    /// </summary>
    public string? AccessionNumberGroup { get; set; }

    /// <summary>
    /// Examination Id.
    /// </summary>
    public List<string>? ExaminationId { get; set; }

    /// <summary>
    /// Id to identify the launching application.
    /// </summary>
    public string? ApplicationId { get; set; }

    /// <summary>
    /// If the web browser should be closed.
    /// </summary>
    public bool? ClosePopup { get; set; }

    /// <summary>
    /// Start the application to initialize it, then stop
    /// </summary>
    public bool? Initialize { get; set; }

    /// <summary>
    /// Frame number
    /// NOTE: The url should contain a one-based frame number!
    ///       (Which is what dicom uses.)
    /// </summary>
    public int? OneBasedFrameNumber { get; set; }

    /// <summary>
    /// Sop instance uid
    /// </summary>
    public string? SopInstanceUid { get; set; }

    /// <summary>
    /// Gets the sequence of command guids or named commands that should be executed when url syncing.
    /// </summary>
    /// <value>
    /// The sequence of command guids or named commands corresponding to the IDS7 UI commands that should be executed.
    /// </value>
    public List<string>? Ids7Commands { get; set; }

    /// <summary>
    /// Enum version of <see cref="Ids7Commands"> that will will populate the same query string parameter
    /// </summary>
    public Ids7CommandEnum? Ids7Command { get; set; }

    /// <summary>
    /// Which command that should be performed by UniView
    /// </summary>
    public UniViewCommandEnum? UniViewCommand { get; set; }

    /// <summary>
    /// UniView layout on launch, i.e disabling or enabling UI components.
    /// </summary>
    public UniViewLayoutEnum? UniViewLayout { get; set; }

    /// <summary>
    /// Which command that should be performed by the Pathology window
    /// </summary>
    public string? PathologyCommand { get; set; }

    /// <summary>
    /// Decides whether or not user will be able to change patient.
    /// </summary>
    public bool? AllowPatientChange { get; set; }

    /// <summary>
    /// Decides whether or not user will ONLY be able to see the examination(s) in the url launch.
    /// </summary>
    public bool? LimitedAccess { get; set; }

    /// <summary>
    /// Returns arguments needed to create the startup presentation which
    /// is used by the thumbnail control.
    /// </summary>
    public StartupPresentationData? StartupPresentation { get; set; }

    /// <summary>
    /// Patient name
    /// </summary>
    public string? PatientName { get; set; }

    /// <summary>
    /// Patient birthdate
    /// </summary>
    public DateTime? PatientBirthdate { get; set; }

    /// <summary>
    /// Patient sex
    /// </summary>
    public string? PatientSex { get; set; }

    /// <summary>
    /// Referring unit
    /// </summary>
    public string? ReferringUnit { get; set; }

    /// <summary>
    /// HIS ID
    /// </summary>
    public string? HisId { get; set; }

    /// <summary>
    /// Decides whether last assignment remembered should be used or not.
    /// </summary>
    public bool? AutoselectLastAssignment { get; set; }

    /// <summary>
    /// A command string used by order management to decide what kind of external launch we
    /// want to perform
    /// </summary>
    public OrderManagementCommandEnum? OmCmd { get; set; }

    /// <summary>
    /// Used for managing the IDS7 window focus behavior
    /// </summary>
    public Ids7WindowManagementEnum? Ids7WindowManagement { get; set; }

    /// <summary>
    /// Used for deciding what workspace to start when launching IDS7.
    /// </summary>
    public string? Ids7Workspace { get; set; }

    /// <summary>
    /// Used for opening a 3D bookmark immediately upon launch.
    /// </summary>
    public string? NdBookmark { get; set; }

    /// <summary>
    /// Replaces the default worklist servers with the servers from the given worklist
    /// </summary>
    public string? UseSearchServersFromWorklist { get; set; }

    /// <summary>
    /// True if the 'Extended Patient Search' servers should be included when fetching patient history.
    /// </summary>
    public bool? PromoteExtendedPatientSearchServers { get; set; }

    /// <summary>
    /// Promote a server to query server
    /// </summary>
    public string? PromoteServerToQuery { get; set; }

}
