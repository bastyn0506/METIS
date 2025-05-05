using System;
using System.Net;
using System.Text;
using System.Threading;
using UnityEngine;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Collections; // ← これが必要


public class WebSocketServer : MonoBehaviour
{
    private HttpListener listener;
    private Thread listenerThread;
    private NetworkVisualizer visualizer;
    private PortStatsUI portStatsUI;
    private CurrentConnectionsUI currentConnectionsUI;


    void Start()
    {
        UnityMainThreadDispatcher.Instance();  // ←これは最初に必要

        StartCoroutine(DelayedInit());  // ← 1秒後に初期化するコルーチンを開始
    }

    private IEnumerator DelayedInit()
    {
        yield return new WaitForSeconds(1f);  // ← シーン内のオブジェクトが揃うのを待つ

        visualizer = FindAnyObjectByType<NetworkVisualizer>();
        portStatsUI = FindAnyObjectByType<PortStatsUI>();
        currentConnectionsUI = FindAnyObjectByType<CurrentConnectionsUI>();

        listener = new HttpListener();
        listener.Prefixes.Add("http://*:8765/");
        listener.Start();

        listenerThread = new Thread(new ThreadStart(HandleRequests));
        listenerThread.Start();

        Debug.Log("✅ WebSocketサーバーが起動しました！（1秒遅延初期化）");
    }


    void OnApplicationQuit()
    {
        if (listener != null && listener.IsListening)
        {
            listener.Stop(); // ← これでポート解放
        }
        if (listenerThread != null && listenerThread.IsAlive)
        {
            listenerThread.Join(); // Abortじゃなくて自然終了待ち
        }
    }

    private void HandleRequests()
    {
        while (listener.IsListening)
        {
            try
            {
                HttpListenerContext context = listener.GetContext();
                HttpListenerRequest request = context.Request;

                if (request.HttpMethod == "POST")
                {
                    using (var reader = new System.IO.StreamReader(request.InputStream, request.ContentEncoding))
                    {
                        string body = reader.ReadToEnd();
                        JToken data = JToken.Parse(body);

                        string type = data["type"]?.ToString();

                        // パケット可視化（packet or typeなし）
                        if (string.IsNullOrEmpty(type) || type == "packet")
                        {
                            string src = data["src"]?.ToString();
                            string dst = data["dst"]?.ToString();
                            string srcCountry = data["src_country"]?.ToString();   // ★ 追加
                            string dstCountry = data["dst_country"]?.ToString();   // ★ 追加

                            if (!string.IsNullOrEmpty(src) && !string.IsNullOrEmpty(dst))
                            {
                                UnityMainThreadDispatcher.Instance().Enqueue(() =>
                                {
                                    visualizer.AddConnection(src, dst, srcCountry, dstCountry);
                                });
                            }
                        }
                        // ポート×IP統計
                        else if (type == "port_ip_stats")
                        {
                            var portIpStats = data["port_ip_counts"] as JObject;

                            if (portIpStats != null && portStatsUI != null)
                            {
                                var dict = new Dictionary<int, Dictionary<string, int>>();

                                foreach (var portEntry in portIpStats)
                                {
                                    int port = int.Parse(portEntry.Key);
                                    var ipDict = new Dictionary<string, int>();

                                    foreach (var ipEntry in (JObject)portEntry.Value)
                                    {
                                        ipDict[ipEntry.Key] = (int)ipEntry.Value;
                                    }

                                    dict[port] = ipDict;
                                }

                                Debug.Log($"📥 ポートIP統計受信: ポート数 {dict.Count}");


                                UnityMainThreadDispatcher.Instance().Enqueue(() =>
                                {
                                    portStatsUI.UpdatePortIPStats(dict);
                                });
                            }
                        }


                        else if (type == "ip_port_stats")
                        {
                            var ipPorts = data["ip_ports"] as JObject;

                            if (ipPorts != null && currentConnectionsUI != null)
                            {
                                var dict = new Dictionary<string, List<int>>();

                                foreach (var ipEntry in ipPorts)
                                {
                                    var ip = ipEntry.Key;
                                    var ports = new List<int>();

                                    foreach (var port in (JArray)ipEntry.Value)
                                    {
                                        ports.Add((int)port);
                                    }

                                    dict[ip] = ports;
                                }

                                UnityMainThreadDispatcher.Instance().Enqueue(() =>
                                {
                                    currentConnectionsUI.UpdateIPPortStats(dict);
                                });
                            }
                        }

                        else if (type == "ip_traffic_stats")
                        {
                            var ipTrafficCounts = data["ip_traffic_counts"] as JObject;

                            if (ipTrafficCounts != null && currentConnectionsUI != null)
                            {
                                var dict = new Dictionary<string, int>();

                                foreach (var ipEntry in ipTrafficCounts)
                                {
                                    string ip = ipEntry.Key;
                                    int count = (int)ipEntry.Value;
                                    dict[ip] = count;
                                }

                                UnityMainThreadDispatcher.Instance().Enqueue(() =>
                                {
                                    currentConnectionsUI.UpdateIPTrafficStats(dict);  // ★ここでUIに渡す
                                });
                            }
                        }

                        // ★ IP×国名情報を受け取る
                        else if (type == "ip_country_stats")
                        {
                            var ipCountries = data["ip_countries"] as JObject;

                            if (ipCountries != null && currentConnectionsUI != null)
                            {
                                var dict = new Dictionary<string, string>();

                                foreach (var ipEntry in ipCountries)
                                {
                                    string ip = ipEntry.Key;
                                    string country = ipEntry.Value?.ToString() ?? "Unknown";

                                    dict[ip] = country;
                                }

                                UnityMainThreadDispatcher.Instance().Enqueue(() =>
                                {
                                    currentConnectionsUI.UpdateIPCountryStats(dict);
                                });
                            }
                        }

                        //スキャンアラート受け取る
                        else if (type == "scan_alert")
                        {
                            string srcIp = data["src_ip"]?.ToString();

                            if (!string.IsNullOrEmpty(srcIp))
                            {
                                UnityMainThreadDispatcher.Instance().Enqueue(() =>
                                {
                                    visualizer?.TriggerScanAlert(srcIp);
                                });
                            }
                        }


                        else if (type == "danger_ports_update")  // 👈 ここを追加！
                        {
                            var dangerPortsArray = data["ports"] as JArray;
                            if (dangerPortsArray != null && portStatsUI != null)
                            {
                                var ports = new List<int>();
                                foreach (var port in dangerPortsArray)
                                {
                                    ports.Add((int)port);
                                }

                                UnityMainThreadDispatcher.Instance().Enqueue(() =>
                                {
                                    portStatsUI.UpdateDangerPorts(ports);
                                });

                                Debug.Log($"⚠️ Unity側で危険ポートを更新: {string.Join(", ", ports)}");
                            }
                        }
                    }
                }

                // レスポンス返す
                HttpListenerResponse response = context.Response;
                string responseString = "{\"status\":\"ok\"}";
                byte[] buffer = Encoding.UTF8.GetBytes(responseString);
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
                response.Close();
            }
            catch (Exception ex)
            {
                Debug.LogWarning("⚠️ WebSocket受信エラー: " + ex.Message);
            }
        }
    }
}


