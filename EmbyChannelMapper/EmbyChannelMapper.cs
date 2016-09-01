using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Net;
using System.Security.Cryptography;
using RestSharp;
using Newtonsoft.Json.Linq;
using System.Threading;
using CommandLine;
using CommandLine.Text;
using System.IO;

namespace EmbyChannelMapper
{
    class EmbyChannelMapper
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
        ///
        static void Main(string[] args)
        {
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
                if (options.Server == null)
                {
                    Console.WriteLine("No server defined. Hit Enter to Exit...");
                    Console.ReadLine();
                    Environment.Exit(100);
                }
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

                //Check if server is reachable
                if (!CheckForInternetConnection(embySite))
                {
                    if (options.Server.StartsWith("http://") && !CheckForInternetConnection("https://" + options.Server))
                    {
                        Console.WriteLine("Server is not reachable or is not an Emby Server. Hit Enter to Exit...");
                        Console.ReadLine();
                        Environment.Exit(100);
                    }
                    else embySite = "https://" + options.Server;
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
            var cancelScheduleRequest = new RestRequest("ScheduledTasks/Running/" + refreshGuideId, Method.POST);
            cancelScheduleRequest.AddHeader("X-MediaBrowser-Token", authToken);
            var cancelScheduleResponse = client.Execute(cancelScheduleRequest);
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

        private static void UpdateEmbyChannelMappings(string embySite, string authToken, string providerId, string refreshGuideId, Dictionary<int,string> channelMap)
        {
            var client = new RestClient(embySite);
            var postRequest = new RestRequest();
            int i = 0;
            Thread cancelThread = new Thread(() =>
            {
                while (true)
                {
                    var cancelScheduleRequest = new RestRequest("ScheduledTasks/Running/" + refreshGuideId, Method.DELETE);
                    cancelScheduleRequest.AddHeader("X-MediaBrowser-Token", authToken);
                    var cancelScheduleResponse = client.Execute(cancelScheduleRequest);
                    client.ExecuteAsync(cancelScheduleRequest, response2 =>
                    {
                        //Console.WriteLine(response2.Content);
                    });
                    Thread.Sleep(500);
                }
            });
            cancelThread.Start();
            foreach (KeyValuePair<int,string> curChanMap in channelMap)
            {
                i++;
                var cancelScheduleRequest = new RestRequest("ScheduledTasks/Running/" + refreshGuideId, Method.DELETE);
                cancelScheduleRequest.AddHeader("X-MediaBrowser-Token", authToken);
                var cancelScheduleResponse = client.Execute(cancelScheduleRequest);
                postRequest = new RestRequest("LiveTv/ChannelMappings/", Method.POST);
                postRequest.AddHeader("X-MediaBrowser-Token", authToken);
                postRequest.AddParameter("ProviderId", providerId);
                postRequest.AddParameter("TunerChannelNumber", curChanMap.Key);
                postRequest.AddParameter("ProviderChannelNumber", curChanMap.Value);
                client.ExecuteAsync(postRequest, response => {                 
                    var content = response.Content;
                    while (content.Equals(""))
                    {
                        client.Execute(cancelScheduleRequest);
                        response = client.Execute(postRequest);
                        content = response.Content;
                    }

                    if (content.Contains("Sequence contains no matching element"))
                    {
                        Console.WriteLine("Channel: " + curChanMap.Key + " does not exist on your server. Skipping...");
                    }
                    else Console.WriteLine("Channel: " + curChanMap.Key + " Mapped: " + curChanMap.Value + ": \n" + response.Content);
                });
            }

            //Wait 10 seconds so the cancelThread can cancel the last one.
            Thread.Sleep(10000);
            cancelThread.Abort();
        }

        private static string EmbyAuthenticate(string embySite, string username, string password)
        { 
            string sha1Password = SHA1HashPassword(password);
            string md5Password = MD5HashPassword(password);
            var client = new RestClient(embySite);
            var request = new RestRequest("Users/AuthenticateByName/", Method.POST);
            request.AddParameter("Username", username);
            request.AddParameter("Password", sha1Password);
            request.AddParameter("PasswordMd5", md5Password);
            request.AddHeader("Authorization", "MediaBrowser UserId=\"\", Client=\"ChannelMapper\", Device=\"ChannelMapper\", DeviceId=\"ChannelMapper\", Version=\"1.0.0.0\"");

            IRestResponse response = client.Execute(request);
            var content = response.Content;
            if(content.Contains("Invalid user or password entered."))
            {
                return "Invalid username or password entered.";
            }
            int i = 0;
            while (content == null || content.Equals(""))
            {
                i++;
                Console.WriteLine("Content is Null. Retrying...");
                response = client.Execute(request);
                content = response.Content;
                if (i > 6)
                {
                    Console.WriteLine("Could not get Authentication Token. Hit Enter to Exit...");
                    Console.ReadLine();
                    Environment.Exit(101);
                }
            }

            dynamic user = JObject.Parse(content);
            
            return user.AccessToken;
        }

        private static string GrabProviderId(string embySite, string authToken)
        {
            var client = new RestClient(embySite);
            var request = new RestRequest("Startup/Configuration/", Method.GET);
            request.AddHeader("X-MediaBrowser-Token", authToken);

            IRestResponse response = client.Execute(request);

            var content = response.Content;
            int i = 0;
            while (content == null || content.Equals(""))
            {
                i++;
                Console.WriteLine("Content is Null. Retrying...");
                response = client.Execute(request);
                content = response.Content;
                if (i > 6)
                {
                    Console.WriteLine("Could not get Provider Id. Hit Enter to Exit...");
                    Console.ReadLine();
                    Environment.Exit(102);
                }
            }

            dynamic config = JObject.Parse(content);

            if(config.LiveTvGuideProviderId == null)
            {
                Console.WriteLine(content);
            }
            return config.LiveTvGuideProviderId;
        }

        private static string GrabRefreshGuideId(string embySite, string authToken)
        {
            var client = new RestClient(embySite);
            var request = new RestRequest("/ScheduledTasks", Method.GET);
            request.AddHeader("X-MediaBrowser-Token", authToken);

            IRestResponse response = client.Execute(request);

            var content = response.Content;
            int i = 0;
            while (content == null || content.Equals(""))
            {
                i++;
                Console.WriteLine("Content is Null. Retrying...");
                response = client.Execute(request);
                content = response.Content;
                if (i > 6)
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

        public static bool CheckForInternetConnection(String server)
        {
            try
            {
                var client = new RestClient(server);
                var request = new RestRequest("System/Ping", Method.POST);
                IRestResponse response = client.Execute(request);
                if (response.Content.Equals("Emby Server"))
                    return true;
                else return false;
            }
            catch
            {
                return false;
            }
        }

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
