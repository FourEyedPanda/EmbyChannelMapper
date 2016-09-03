using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Security.Cryptography;
using RestSharp;
using Newtonsoft.Json.Linq;
using CommandLine;
using CommandLine.Text;
using System.IO;
using System.Timers;

namespace EmbyChannelMapper
{
    class EmbyChannelMapper
    {
        /// <summary>
        /// Main Thread
        /// </summary>
        /// <param name="args">Arguments available, File Name, Server Name, ApiKey, Username, Password</param>
        ///
        static void Main(string[] args)
        {
            //Start the clock
            var watch = System.Diagnostics.Stopwatch.StartNew();
            
            //Initialize variables needed
            string userName = null;
            string embySite = null;
            string password = null;
            string xmltvFile = null;
            string authToken = null;

            //Command Line Parsing
            var options = new Options();

            if (args.Length == 0)
            {
                Console.WriteLine("No arguments defined. Hit Enter to Exit...");
                Console.ReadLine();
                Environment.Exit(100);
            }

            if (CommandLine.Parser.Default.ParseArguments(args, options)){
                //Check if file Exists.
                //if (options.Server == null)
                {
                    Console.WriteLine("No server defined. Hit Enter to Exit...");
                    Console.ReadLine();
                    Environment.Exit(100);
                }

                //Add http if http or https is not defined
                else
                {
                    embySite = options.Server;
                    if (!embySite.StartsWith("http://") && !embySite.StartsWith("https://"))
                    {
                        embySite = "http://" + embySite;
                    }
                }

                
                if (options.InputFile == null || !File.Exists(options.InputFile))
                {
                    Console.WriteLine("File does not exist or is undefined. Hit Enter to Exit...");
                    Console.ReadLine();
                    Environment.Exit(100);
                }
                else xmltvFile = options.InputFile;

                //Check if server is reachable. Test out https and http if it was not defined.
                if (!CheckForInternetConnection(embySite))
                {
                    if (options.Server.StartsWith("http://"))
                    {
                        if (!CheckForInternetConnection("https://" + options.Server))
                        {
                            Console.WriteLine("Server is not reachable or is not an Emby Server. Hit Enter to Exit...");
                            Console.ReadLine();
                            Environment.Exit(100);
                        }
                        else embySite = "https://" + options.Server;
                    }
                    else
                    {
                        Console.WriteLine("Server is not reachable or is not an Emby Server. Hit Enter to Exit...");
                        Console.ReadLine();
                        Environment.Exit(100);
                    }
                }

                //Check if using APIKey
                if (options.APIKey == null)
                {
                    //If not using APIKey check to make sure Username and Password
                    if (options.UserName == null)
                    {
                        Console.WriteLine("Username or APIKey is required. Hit Enter to Exit...");
                        Console.ReadLine();
                        Environment.Exit(100);
                    }
                    else
                    {
                        if (options.Password == null)
                        {
                            Console.WriteLine("Password is required if using username. Hit Enter to Exit...");
                            Console.ReadLine();
                            Environment.Exit(100);
                        }
                        else
                        {
                            userName = options.UserName;
                            password = options.Password;
                        }
                    }
                }
                else authToken = options.APIKey;
            }
            else
            {
                Console.WriteLine(CommandLine.Parser.DefaultExitCodeFail);
                Environment.Exit(100);
            }



            //Command Line finished parsing. Start the parsing of the xmltv file and put it in the dictionary.
            Dictionary<int, string> channelMap = null;
            Console.WriteLine("Starting to parse file.");
            try
            {
                channelMap = XmlToChannelMappings(xmltvFile);
            }
            catch(System.Xml.XmlException)
            {
                Console.WriteLine("File is not XML. Can't parse file. Hit Enter to Exit...");
                Console.ReadLine();
                Environment.Exit(103);
            }
            Console.WriteLine("Created mapping logic from file: " + xmltvFile);
            Console.WriteLine("Running calls against: " + embySite);
            
            //If authToken is null, username and password was used. Get authToken with that username and password.
            if (authToken == null)
            {
                authToken = EmbyAuthenticate(embySite, userName, password);
                if (authToken == null)
                {
                    Console.WriteLine("Unable to get AuthToken");
                    Console.ReadLine();
                    Environment.Exit(102);
                }
                if (authToken.Contains("Invalid username or password entered."))
                {
                    Console.WriteLine("Invalid username or password entered. Hit Enter to Exit...");
                    Console.ReadLine();
                    Environment.Exit(101);
                }
                
                else Console.WriteLine("Got AccessToken: " + authToken);
            }

            //Grab providerId that is needed to put the mappings in.
            string providerId = GrabProviderId(embySite, authToken);
            Console.WriteLine("Got ProviderID: " + providerId);

            //Grab ID for the Refresh Guide task so we can cancel it
            string refreshGuideId = GrabRefreshGuideId(embySite, authToken);
            Console.WriteLine("Got Refresh Guide Task Id: " + refreshGuideId);
            
            //Start mapping the channels.
            Console.WriteLine("Starting to map channels in emby...");
            UpdateEmbyChannelMappings(embySite, authToken, providerId, refreshGuideId, channelMap);

            //Now that all mappings are done, let's Refresh Guide Data
            var client = new RestClient(embySite);
            client.Timeout = 2000; //Don't want to wait for response as Refresh Guide Task is long.
            var cancelScheduleRequest = new RestRequest("ScheduledTasks/Running/" + refreshGuideId, Method.POST);
            cancelScheduleRequest.AddHeader("X-MediaBrowser-Token", authToken);
            client.Execute(cancelScheduleRequest);
            client.ExecuteAsync(cancelScheduleRequest, response =>
            {
            });

            //We are done!!
            watch.Stop();
            TimeSpan ts = watch.Elapsed;
            string timeTaken = String.Format("{0:00}:{1:00}:{2:00}.{3:00}", ts.Hours, ts.Minutes, ts.Seconds, ts.Milliseconds / 10);
            Console.WriteLine("Finished mapping channels in. Time taken: " + timeTaken);
            Console.WriteLine("Hit Enter to Exit...");
            Console.ReadLine();
            Environment.Exit(0);
        }

        /// <summary>
        /// Create a dictionary mapping of XMLTV Channel Id to Emby Tuner Channel #
        /// </summary>
        /// <param name="inFile">XMLTV file to parse</param>
        /// <returns>Dictionary<(int) EmbyTunerChannel, (string) XMLTV Channel ID></returns>
        private static Dictionary<int,string> XmlToChannelMappings(string inFile)
        {
            Dictionary<int, string> result = new Dictionary<int, string>();
            XmlReaderSettings xrs = new XmlReaderSettings();
            xrs.DtdProcessing = DtdProcessing.Ignore;
            XmlReader reader = XmlReader.Create(inFile,xrs);
            string channelId = null;
            while (true)
            {
                reader.MoveToContent();         
                int channelNumInt = -1;
                if (reader.NodeType == XmlNodeType.Element && reader.Name == "channel")
                {
                    channelId = reader.GetAttribute("id");
                    reader.Read();
                }
                else if (reader.NodeType == XmlNodeType.Element && reader.Name == "display-name")
                {
                    reader.Read();
                    if (reader.NodeType == XmlNodeType.Text)
                    {
                        string channelNumStr = reader.Value;
                        if (Int32.TryParse(channelNumStr, out channelNumInt))
                        {
                            result.Add(channelNumInt, channelId);
                            Console.WriteLine("Channel: " + channelNumInt + " ID: " + channelId);
                            if (reader.ReadToFollowing("channel"))
                                continue;
                            else break;
                        }
                    }
                }
                else
                {
                    if (!reader.Read())
                        break;
                }
            }
            return result;
        }

        /// <summary>
        /// Update the Mappings using REST calls against the Emby Server
        /// </summary>
        /// <param name="embySite">URL for Emby Server</param>
        /// <param name="authToken">Authentication Token</param>
        /// <param name="providerId">Live TV Guide Provider ID</param>
        /// <param name="refreshGuideId">Refresh Guide Scheduled Task ID</param>
        /// <param name="channelMap">Dictionary of Channel Mappings</param>
        private static void UpdateEmbyChannelMappings(string embySite, string authToken, string providerId, string refreshGuideId, Dictionary<int,string> channelMap)
        {
            var client = new RestClient(embySite);
            client.Timeout = 2000;
            var postRequest = new RestRequest();

            //Create Timer to cancel Refresh Guide Task as it holds up the mapping calls.
            System.Timers.Timer cancelTimer = new System.Timers.Timer();
            cancelTimer.Elapsed += (sender, e) => cancelRefreshGuideEvent(sender, e, embySite, authToken, refreshGuideId);
            cancelTimer.Interval = 1000;
            cancelTimer.Start();

            //For each Channel Mapping in Dictionary, try and import it.
            foreach (KeyValuePair<int,string> curChanMap in channelMap)
            {
                postRequest = new RestRequest("LiveTv/ChannelMappings/", Method.POST);
                postRequest.AddHeader("X-MediaBrowser-Token", authToken);
                postRequest.AddParameter("ProviderId", providerId);
                postRequest.AddParameter("TunerChannelNumber", curChanMap.Key);
                postRequest.AddParameter("ProviderChannelNumber", curChanMap.Value);
                var response = client.Execute(postRequest);
                var content = response.Content;
                int i = 0;
                while (content.Equals("") || content.Contains("504 Gateway Time-out"))
                {
                    response = client.Execute(postRequest);
                    content = response.Content;
                    if (i > 10)
                    {
                        Console.WriteLine(curChanMap.Key + ", " + curChanMap.Value);
                        Console.WriteLine(content);
                        Console.WriteLine(response.ErrorMessage);
                        Console.WriteLine(response.ErrorException);
                    }
                }

                //The channel does not exist in Emby so we can skip it.
                if (content.Contains("Sequence contains no matching element"))
                {
                    Console.WriteLine("Channel: " + curChanMap.Key + " does not exist on your server. Skipping...");
                }
                else Console.WriteLine("Channel: " + curChanMap.Key + " Mapped: " + curChanMap.Value + ": \n" + response.Content);
            }
            cancelTimer.Stop();

        }

        /// <summary>
        /// REST Call to get AuthenticationToken with username and password
        /// </summary>
        /// <param name="embySite">URL For Emby Server</param>
        /// <param name="username">Emby User Username</param>
        /// <param name="password">Emby User Password</param>
        /// <returns>User Authentication Token</returns>
        private static string EmbyAuthenticate(string embySite, string username, string password)
        { 
            string sha1Password = SHA1HashPassword(password);
            string md5Password = MD5HashPassword(password);
            var client = new RestClient(embySite);
            var request = new RestRequest("Users/AuthenticateByName", Method.POST);
            request.AddHeader("Authorization", "MediaBrowser UserId=\"\", Client=\"ChannelMapper\", Device=\"ChannelMapper\", DeviceId=\"ChannelMapper\", Version=\"1.0.0.0\"");
            request.AddParameter("Username", username);
            request.AddParameter("Password", sha1Password);
            request.AddParameter("PasswordMd5", md5Password);
            

            IRestResponse response = client.Execute(request);
            var content = response.Content;
            if(content.Contains("Invalid user or password entered."))
            {
                return "Invalid username or password entered.";
            }
            int i = 0; //count of retries.

            //If content is empty or timed out retry.
            while (content.Equals("") || content.Contains("504 Gateway Time-out"))
            {
                i++;
                Console.WriteLine("Content is Null. Retrying...");
                response = client.Execute(request);
                content = response.Content;
                if (i > 6) // after 6 retires, give up.
                {
                    Console.WriteLine("Could not get Authentication Token. Hit Enter to Exit...");
                    Console.ReadLine();
                    Environment.Exit(101);
                }
            }

            //Parse Object then return AccessToken.
            dynamic user = JObject.Parse(content);
            
            return user.AccessToken;
        }

        /// <summary>
        /// Grab providerID for LiveTv Guide Provider to add Channel Mappings to
        /// </summary>
        /// <param name="embySite">Emby Server URL</param>
        /// <param name="authToken">Emby Authentication Token</param>
        /// <returns>LiveTv Guide Provider ID</returns>
        private static string GrabProviderId(string embySite, string authToken)
        {
            var client = new RestClient(embySite);
            var request = new RestRequest("Startup/Configuration/", Method.GET);
            request.AddHeader("X-MediaBrowser-Token", authToken);

            IRestResponse response = client.Execute(request);

            var content = response.Content;
            int i = 0; //Count of Retries.

            //If content is empty or timed out retry.
            while (content.Equals("") || content.Contains("504 Gateway Time-out"))
            {
                i++;
                Console.WriteLine("Content is Null. Retrying...");
                response = client.Execute(request);
                content = response.Content;
                if (i > 6) //After 6 retries, give up.
                {
                    Console.WriteLine("Could not get Provider Id. Hit Enter to Exit...");
                    Console.ReadLine();
                    Environment.Exit(102);
                }
            }

            //Parse the Object and then grab LiveTVGuideProviderID
            dynamic config = JObject.Parse(content);
            return config.LiveTvGuideProviderId;
        }

        /// <summary>
        /// Grabs the Refresh Guide Task ID so we can cancel it as inserting a channel mapping causes it to fire
        /// and it holds up the next channel mapping REST calls.
        /// </summary>
        /// <param name="embySite">Emby Server URL</param>
        /// <param name="authToken">Emby Authentication Token</param>
        /// <returns></returns>
        private static string GrabRefreshGuideId(string embySite, string authToken)
        {
            var client = new RestClient(embySite);
            var request = new RestRequest("/ScheduledTasks", Method.GET);
            request.AddHeader("X-MediaBrowser-Token", authToken);

            IRestResponse response = client.Execute(request);

            var content = response.Content;
            int i = 0; //Count of retries.

            //If content is empty or timed out, retry.
            while (content.Equals("") || content.Contains("504 Gateway Time-out"))
            {
                i++;
                Console.WriteLine("Content is Null. Retrying...");
                response = client.Execute(request);
                content = response.Content;
                if (i > 6) //After 6 retries, give up.
                {
                    Console.WriteLine("Could not get Refresh Guide Task Id. Hit Enter to Exit...");
                    Console.ReadLine();
                    Environment.Exit(103);
                }
            }
            content = content.Substring(content.IndexOf("\"RefreshGuide\",\"Id\":")+21);
            content = content.Substring(0, content.IndexOf("\"},"));
            return content;
        }


        //Method to be used with a timer to cancel the Refresh Guide task every n milliseconds.
        private static void cancelRefreshGuideEvent(object source, ElapsedEventArgs e, string embySite, string authToken, string refreshGuideId)
        {
            var client = new RestClient(embySite);
            client.Timeout = 750;
            var request = new RestRequest("ScheduledTasks/" + refreshGuideId, Method.GET);
            request.AddHeader("X-MediaBrowser-Token", authToken);
            var response = client.Execute(request);
            if (response.Content.Contains("\"State\":\"Running\""))
            {
                var cancelScheduleRequest = new RestRequest("ScheduledTasks/Running/" + refreshGuideId, Method.DELETE);
                cancelScheduleRequest.AddHeader("X-MediaBrowser-Token", authToken);
                var cancelScheduleResponse = client.Execute(cancelScheduleRequest);
            }
        }

        /// <summary>
        /// Creates an SHA1 Hash of the Emby User Password
        /// </summary>
        /// <param name="password">Emby User Password</param>
        /// <returns>SHA1 Hash of Emby User Password</returns>
        private static string SHA1HashPassword(string password)
        {
            SHA1 sha1 = SHA1.Create();
            byte[] passwordBytes = System.Text.Encoding.ASCII.GetBytes(password);
            byte[] hashPasswordByte = sha1.ComputeHash(passwordBytes);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashPasswordByte.Length; i++)
                sb.Append(hashPasswordByte[i].ToString("X2"));
            return sb.ToString();
        }

        /// <summary>
        /// Creates MD5 Hash of Emby User Password
        /// </summary>
        /// <param name="password">Emby User Password</param>
        /// <returns>MD5 Hash of Emby User Password</returns>
        private static string MD5HashPassword(string password)
        {
            MD5 md5 = MD5.Create();
            byte[] passwordBytes = System.Text.Encoding.ASCII.GetBytes(password);
            byte[] hashPasswordByte = md5.ComputeHash(passwordBytes);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashPasswordByte.Length; i++)
                sb.Append(hashPasswordByte[i].ToString("X2"));
            return sb.ToString();
        }

        /// <summary>
        /// Check if the site provided is reachable and is actually an Emby Server
        /// </summary>
        /// <param name="server">Test URL</param>
        /// <returns>Boolean reflecting if it is an Emby Server</returns>
        public static bool CheckForInternetConnection(String server)
        {
            var client = new RestClient(server);
            var request = new RestRequest("System/Ping", Method.POST);
            IRestResponse response = client.Execute(request);
            var content = response.Content;
            while (content.Equals("") || content.Contains("504 Gateway Time-out"))
            {
                response = client.Execute(request);
                content = response.Content;
            }
            if (response.Content.Equals("Emby Server")) //Emby ping responds with Emby Server then it is an Emby Server
            {
                return true;
            }
            else return false;
        }

        /// <summary>
        /// Class to help with CommandLineParsing
        /// </summary>
        class Options
        {
            [Option('f', "file",
              HelpText = "Input file to be processed.")]
            public string InputFile { get; set; }

            [Option('a', "APIkey",
              HelpText = "The API Key for emby")]
            public string APIKey { get; set; }

            [Option('u', "Username",
              HelpText = "emby Username")]
            public string UserName { get; set; }

            [Option('p', "Password", 
              HelpText = "Password for user")]
            public string Password { get; set; }

            [Option('s', "Server",
              HelpText = "The server for emby (ex:http://emby.com:8096/)")]
            public string Server { get; set; }

            [ParserState]
            public IParserState LastParserState { get; set; }

            [HelpOption]
            public string GetUsage()
            {
                return HelpText.AutoBuild(this,
                  (HelpText current) => HelpText.DefaultParsingErrorsHandler(this, current));
            }
        }
    }
}
