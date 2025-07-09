using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
public static class MonthEndFunction
{
    [FunctionName("MonthEndFunction")]
    public static void Run(
        [TimerTrigger("0 0 0 * * *;0 */15 * 28-31 * *")] TimerInfo myTimer,
        ILogger log)
    {
        DateTime today = DateTime.UtcNow;
        // Determine if today is the last day of the month
        bool isLastDayOfMonth = today.Day == DateTime.DaysInMonth(today.Year, today.Month);
        if (isLastDayOfMonth)
        {
            log.LogInformation($"[Month-End] Running every 15 minutes on the last day of the month: {today}");
            // Add your month-end logic here
        }
        else if (today.Hour == 0 && today.Minute == 0)
        {
            log.LogInformation($"[Daily] Running once daily at midnight: {today}");
            // Add your daily logic here
        }
        else
        {
            log.LogInformation($"[Skipped] Not the last day or midnight: {today}");
        }
    }
}
 

using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using NCrontab;

public static class DynamicTimerFunction
{
    [FunctionName("DynamicTimerFunction")]
    public static async Task Run(
        [TimerTrigger("0 */5 * * * *")] TimerInfo myTimer,
        ILogger log)
    {
        var now = DateTime.UtcNow;
        var schedules = await GetActiveSchedulesFromDb();

        foreach (var cron in schedules)
        {
            var schedule = CrontabSchedule.Parse(cron);
            var nextOccurrence = schedule.GetNextOccurrence(now.AddMinutes(-5), now);

            if (nextOccurrence != DateTime.MinValue)
            {
                log.LogInformation($"[Triggered] Schedule matched: {cron} at {now}");
                // Your business logic here
            }
        }
    }

    private static async Task<List<string>> GetActiveSchedulesFromDb()
    {
        var cronList = new List<string>();
        var connectionString = Environment.GetEnvironmentVariable("SqlConnectionString");

        using (var conn = new SqlConnection(connectionString))
        {
            await conn.OpenAsync();
            var cmd = new SqlCommand("SELECT CronExpression FROM TimerSchedules WHERE IsActive = 1", conn);
            var reader = await cmd.ExecuteReaderAsync();

            while (await reader.ReadAsync())
            {
                cronList.Add(reader.GetString(0));
            }
        }

        return cronList;
    }
}

using NCrontab;

public static bool ShouldRunNow(string cronExpression, DateTime currentTimeUtc, int windowMinutes = 5)
{
    try
    {
        var schedule = CrontabSchedule.Parse(cronExpression);
        var previousWindow = currentTimeUtc.AddMinutes(-windowMinutes);
        var nextOccurrence = schedule.GetNextOccurrence(previousWindow, currentTimeUtc);

        // If a valid occurrence is found in the last window, return true
        return nextOccurrence != DateTime.MinValue;
    }
    catch (Exception ex)
    {
        // Log or handle invalid CRON expressions
        Console.WriteLine($"Invalid CRON: {cronExpression} - {ex.Message}");
        return false;
    }
}


var cron = "0 */15 * * * *"; // Every 15 minutes
var schedule = CrontabSchedule.Parse(cron);

var now = DateTime.UtcNow;
var windowStart = now.AddMinutes(-5);

var next = schedule.GetNextOccurrence(windowStart, now);

if (next != DateTime.MinValue)
{
    Console.WriteLine($"Scheduled to run at: {next}");
}
else
{
    Console.WriteLine("No scheduled run in this window.");
}

 
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using System;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace YourNamespace
{
    public partial class MainForm : Form
    {
        private SecretClient _secretClient;

        public MainForm()
        {
            InitializeComponent();
            InitializeKeyVaultClient();
        }

        private void InitializeKeyVaultClient()
        {
            var keyVaultName = "your-key-vault-name";
            var kvUri = $"https://{keyVaultName}.vault.azure.net";
            _secretClient = new SecretClient(new Uri(kvUri), new DefaultAzureCredential());
        }

        private async void GetSecretButton_Click(object sender, EventArgs e)
        {
            string secretName = "your-secret-name";
            var secret = await GetSecretAsync(secretName);
            MessageBox.Show($"Secret Value: {secret}");
        }

        private async Task<string> GetSecretAsync(string secretName)
        {
            KeyVaultSecret secret = await _secretClient.GetSecretAsync(secretName);
            return secret.Value;
        }
    }
}
 
using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace SampleFunctionAppTemplates
{
    public static class SingletonHttpTriggered
    {
        [FunctionName("SingletonHttpTriggered")]
        [Singleton]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string name = req.Query["name"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;

            string responseMessage = string.IsNullOrEmpty(name)
                ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
                : $"Hello, {name}. This HTTP triggered function executed successfully.";

            return new OkObjectResult(responseMessage);
        }
    }
}
 

using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Extensions.OpenApi.Core.Attributes;
using Microsoft.Azure.WebJobs.Extensions.OpenApi.Core.Enums;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
namespace SampleFunctionAppTemplates
{
    public class HttpTriggeredSingleton
    {         private readonly ILogger<HttpTriggeredSingleton> _logger;

        public HttpTriggeredSingleton(ILogger<HttpTriggeredSingleton> log)         {         _logger = log;        }

        [FunctionName(nameof(HttpTriggeredSingleton))]
        [OpenApiOperation(operationId: "Run", tags: new[] { "name" })]
        [OpenApiSecurity("function_key", SecuritySchemeType.ApiKey, Name = "code", In = OpenApiSecurityLocationType.Query)]
        [OpenApiParameter(name: "name", In = ParameterLocation.Query, Required = true, Type = typeof(string), Description = "The **Name** parameter")]
        [OpenApiResponseWithBody(statusCode: HttpStatusCode.OK, contentType: "text/plain", bodyType: typeof(string), Description = "The OK response")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");

            string name = req.Query["name"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;

            string responseMessage = string.IsNullOrEmpty(name)
                ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
                : $"Hello, {name}. This HTTP triggered function executed successfully.";

            return new OkObjectResult(responseMessage);
        }
    }
}
 
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Extensions.OpenApi.Core.Attributes;
using Microsoft.Azure.WebJobs.Extensions.OpenApi.Core.Enums;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;

namespace SampleFunctionAppTemplates
{
    public class HttpTriggeredWithOpenAPI
    {
        private readonly ILogger<HttpTriggeredWithOpenAPI> _logger;

        public HttpTriggeredWithOpenAPI(ILogger<HttpTriggeredWithOpenAPI> log)
        {
            _logger = log;
        }

        [FunctionName("HttpTriggeredWithOpenAPI")]
        [OpenApiOperation(operationId: "Run", tags: new[] { "name" })]
        [OpenApiSecurity("function_key", SecuritySchemeType.ApiKey, Name = "code", In = OpenApiSecurityLocationType.Query)]
        [OpenApiParameter(name: "name", In = ParameterLocation.Query, Required = true, Type = typeof(string), Description = "The **Name** parameter")]
        [OpenApiResponseWithBody(statusCode: HttpStatusCode.OK, contentType: "text/plain", bodyType: typeof(string), Description = "The OK response")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");
            string name = req.Query["name"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;
            string responseMessage = string.IsNullOrEmpty(name)
                ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
                : $"Hello, {name}. This HTTP triggered function executed successfully.";

            return new OkObjectResult(responseMessage);
        }
    }
}
using System;
using FAPTemplate;
using System.Collections.Generic;

using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Microsoft.VisualBasic;
using FAPTemplate.AzureServices;
namespace SampleFunctionAppTemplates
{
    public class TimerTriggered
    {
        [FunctionName(nameof(TimerTriggered))]
        public static void Run([TimerTrigger("0 */5 * * * *")] TimerInfo myTimer, ILogger log) => log.LogInformation($"C# Timer trigger function executed at: {DateTime.Now}");
        [FunctionName("MultipleTimerTriggred")]
        [FixedDelayRetry(5, "00:00:10")]
        [Singleton]
        [StorageAccount("%StorageAccount%")]
        [NoAutomaticTrigger]
        [STAThread]
        [MTAThread]
        [ServiceBusAccount("%StorageAccount%")]
        public static void AltRun([TimerTrigger("0 */5 * * * *")] TimerInfo myTimer, ILogger log)
        {
            using (log.BeginScope($"<AddYourScope>", $"<AddYourScope> + <ProcessingType>"))
            {     using (log.BeginScope(new Dictionary<string, object>
                {
                    ["Environment"] = "<Add Environment Here>",
                    ["MessageType"] = "<Add Interface/MessageType Here>",
                    ["FileName"] = "<Add File Name Here>",
                    ["MessageID"] = "<Add Message ID Here>",
                    ["BlobContainer"] = "<Add Message ID Here>",
                    ["ServiceBusTopic"] = "<Add Message ID Here>"
                }))
                {
                    // Write your logic Here.
                    //var receivedFileContent = await _blobService.GetBlobStream("<BLOB FileName Here>", "<ContainerName>");
                    log.LogInformation($"C# Timer trigger function executed at: {DateTime.Now}");
                }             }                  }
        [FunctionName("Warmup")]
        public static void Run([WarmupTrigger()] WarmupContext context, ILogger log)
        { 
            //Initialize shared dependencies here
            log.LogInformation("Function App instance is warm.");
        }
    }
} 
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Web;

class Program
{
    static async Task Main()
    {
        // Replace with your Service Bus details
        string serviceNamespace = "Add the Service Bus Name Space Here";
        string topicName = "The Topic/Queue Name goes Here";
        string messageBody = "This is a message.";

        // Create the HTTP client
        using HttpClient client = new();
        // Set the request URI
        string requestUri = $"https://{serviceNamespace}.servicebus.windows.net/{topicName}/messages?timeout=60";
        string sasToken = GetSasToken(requestUri, "Add Shared Access Policy Key Name", "Add Shared Access Policy Key Value", TimeSpan.FromDays(1));
        // Create the message content with corrected content type
        StringContent content = new(messageBody, Encoding.UTF8, "application/xml");

        // Add required headers
        client.DefaultRequestHeaders.Add("Authorization", sasToken);
        string messageId = Guid.NewGuid().ToString();

        //Setting the broker properties
        Dictionary<string, string> brokerProperties = new()
        {
            { "CorrelationId", messageId },
            { "SessionId", "123" }
        };
        // Adding the BrokerProperties header with SessionId
        client.DefaultRequestHeaders.Add("BrokerProperties", JsonSerializer.Serialize(brokerProperties));

        //Setting the Custom Properties
        client.DefaultRequestHeaders.Add("message_type", "My test");
        client.DefaultRequestHeaders.Add("message_id", messageId);
        client.DefaultRequestHeaders.ExpectContinue = true;

        // Service Bus Endpoint Call
        HttpResponseMessage response = await client.PostAsync(requestUri, content);

        // Check the response
        if (response.IsSuccessStatusCode)
        {
            Console.WriteLine($"Message sent successfully with status code: {response.StatusCode}");
        }
        else
        {
            Console.WriteLine($"Failed to send message. Status code: {response.StatusCode}, Reason: {response.ReasonPhrase}");
        }
    }

    public static string GetSasToken(string resourceUri, string keyName, string key, TimeSpan ttl)
    {
        var expiry = GetExpiry(ttl);
        string stringToSign = HttpUtility.UrlEncode(resourceUri) + "\n" + expiry;
        HMACSHA256 hmac = new(Encoding.UTF8.GetBytes(key));
        var signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));
        var sasToken = string.Format(CultureInfo.InvariantCulture, "SharedAccessSignature sr={0}&sig={1}&se={2}&skn={3}",
        HttpUtility.UrlEncode(resourceUri), HttpUtility.UrlEncode(signature), expiry, keyName);
        return sasToken;
    }

    private static string GetExpiry(TimeSpan ttl)
    {
        TimeSpan expirySinceEpoch = DateTime.UtcNow - new DateTime(1970, 1, 1) + ttl;
        return Convert.ToString((int)expirySinceEpoch.TotalSeconds);
    }
}
 
Send Message to Azure Service Bus Using API Call
Prerequisites:
1.	A Service Bus endpoint URL
2.	Shared Access Token (SAS) Token
3.	Postman to test 
Here, we are going to send the message to the Service Bus (SB) using the Service Bus API call.
The Api URL looks as below:
http{s}://{serviceNamespace}.servicebus.windows.net/{queuePath or topicPath}/messages 

The mandatory properties that need to be passed in the request header are Authorization , Content-Type and BrokerProperties.
Here, Authorization can be done in 2 ways:
1.	Azure Active Directory (Azure AD) JSON Web Token (JWT)
2.	Shared Access Signature (SAS) Token
Here, we are going to use the SAS token and will write some prerequisite scripts to make it work in the request call.
Script
const sharedKeyName = "<Shared Access Key Name>" 
const sharedKey = "<Shared Access Key>"
const uri = "https://{Service Bus Name}.servicebus.windows.net/{Topic Name/Queue Name}"

function createSharedAccessToken(uri, saName, saKey) { 
    if (!uri || !saName || !saKey) { 
            throw "Missing required parameter"; 
        } 
    var encoded = encodeURIComponent(uri); 
    var now = new Date(); 
    var week = 60*60*24*7;
    var ttl = Math.round(now.getTime() / 1000) + week;
    var signature = encoded + '\n' + ttl;
    const hash = CryptoJS.HmacSHA256(signature, saKey).toString(CryptoJS.enc.Base64)
    return 'SharedAccessSignature sr=' + encoded + '&sig=' +  
        encodeURIComponent(hash) + '&se=' + ttl + '&skn=' + saName; 
}
// Set broker properties e.g. sessionId
const brokerProperties = {
    'SessionId':'123',
   }
// Set broker proerties variable
pm.variables.set("broker_properties", JSON.stringify(brokerProperties));
// Set access token variable
pm.variables.set('access_token', createSharedAccessToken(uri, sharedKeyName, sharedKey));

 

 

 
 

