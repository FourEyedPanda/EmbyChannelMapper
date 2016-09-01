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
            string userName = "ApiUser";
            string embySite = "http://96.232.182.211:8096";
            string password = "embyPasswordTest";
            string xmltvFile = "C:\\zap2xml\\xmltv.xml";
            string authToken = null;
            var options = new Options();
            if (CommandLine.Parser.Default.ParseArguments(args, options)){
                //Check if file Exists.
                if (!File.Exists(options.InputFile))
                {
                    Console.WriteLine("File does not exist.");
                    return;
                }
                else xmltvFile = options.InputFile;

                //Check if server is reachable
                if (!CheckForInternetConnection(options.Server))
                {
                    Console.WriteLine("Server is not reachable.");
                    return;
                }

                //Check if using APIKey
                if (options.APIKey == null)
                {
                    //If not using APIKey check to make sure Username and Password
                    if (options.UserName == null)
                    {
                        Console.WriteLine("Username or APIKey is required.");
                        return;
                    }
                    else
                    {
                        if (options.Password == null)
                        {
                            Console.WriteLine("Password is required if using username.");
                            return;
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

            Dictionary<int, string> channelMap = XmlToChannelMappings(xmltvFile);
            if (authToken == null)
            {
                authToken = EmbyAuthenticate(embySite, userName, password);
            }
            UpdateEmbyChannelMappings(embySite, authToken, channelMap);
            Console.WriteLine("Finished mapping channels.");
            Console.ReadLine();
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

        private static void UpdateEmbyChannelMappings(string embySite, string authToken, Dictionary<int,string> channelMap)
        {
            var client = new RestClient(embySite);
            Console.WriteLine("Got AccessToken: " + authToken);
            string providerId = GrabProviderId(client, authToken);
            Console.WriteLine("Got ProviderID: " + providerId);
            var postRequest = new RestRequest();
            int i = 0;
            Thread cancelThread = new Thread(() =>
            {
                while (true)
                {
                    var cancelScheduleRequest = new RestRequest("ScheduledTasks/Running/3c6a16ed7db828baeb3bb3c1cff74810", Method.DELETE);
                    cancelScheduleRequest.AddHeader("X-MediaBrowser-Token", authToken);
                    var cancelScheduleResponse = client.Execute(cancelScheduleRequest);
                    client.ExecuteAsync(cancelScheduleRequest, response2 =>
                    {
                        //Console.WriteLine(cancelScheduleRequest.Content);
                    });
                    Thread.Sleep(500);
                }
            });
            cancelThread.Start();
            foreach (KeyValuePair<int,string> curChanMap in channelMap)
            {
                i++;
                var cancelScheduleRequest = new RestRequest("ScheduledTasks/Running/3c6a16ed7db828baeb3bb3c1cff74810", Method.DELETE);
                cancelScheduleRequest.AddHeader("X-MediaBrowser-Token", authToken);
                var cancelScheduleResponse = client.Execute(cancelScheduleRequest);
                postRequest = new RestRequest("LiveTv/ChannelMappings/", Method.POST);
                postRequest.AddHeader("Authorization", "MediaBrowser UserId=\"\", Client=\"ChannelMapper\", Device=\"ChannelMapper\", DeviceId=\"ChannelMapper\", Version=\"1.0.0.0\"");
                postRequest.AddHeader("X-MediaBrowser-Token", authToken);
                postRequest.AddParameter("ProviderId", providerId);
                postRequest.AddParameter("TunerChannelNumber", curChanMap.Key);
                postRequest.AddParameter("ProviderChannelNumber", curChanMap.Value);
                client.ExecuteAsync(postRequest, response => {
                    Console.WriteLine(response.Content);
                    var content = response.Content;
                    while (content.Equals(""))
                    {
                        client.Execute(cancelScheduleRequest);
                        response = client.Execute(postRequest);
                        content = response.Content;
                    }
                });
                if (i > 10)
                    break;
            }
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
            Console.WriteLine(response.ErrorMessage);
            Console.WriteLine(response.ErrorException);
            var content = response.Content;
            Console.WriteLine(content);
            if (content == null || content.Equals(""))
            {
                Console.WriteLine("Content is Null");
            }

            dynamic user = JObject.Parse(content);
            
            return user.AccessToken;
        }

        private static string GrabProviderId(RestClient client, string authToken)
        {
            var request = new RestRequest("Startup/Configuration/", Method.GET);
            //request.AddHeader("Authorization", "MediaBrowser UserId=\"\", Client=\"ChannelMapper\", Device=\"ChannelMapper\", DeviceId=\"ChannelMapper\", Version=\"1.0.0.0\"");
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
                if (i > 8)
                    break;
            }

            dynamic config = JObject.Parse(content);

            if(config.LiveTvGuideProviderId == null)
            {
                Console.WriteLine(content);
            }
            return config.LiveTvGuideProviderId;
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
                using (var client = new WebClient())
                {
                    using (var stream = client.OpenRead(server))
                    {
                        return true;
                    }
                }
            }
            catch
            {
                return false;
            }
        }

        class Options
        {
            [Option('f', "file", Required = true,
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

            [Option('s', "Server", Required = true,
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
