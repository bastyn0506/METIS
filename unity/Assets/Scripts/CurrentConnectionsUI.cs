using UnityEngine;
using UnityEngine.UI;
using TMPro;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

public class CurrentConnectionsUI : MonoBehaviour
{
    public NetworkVisualizer networkVisualizer;
    public TextMeshProUGUI ipListText;
    public ScrollRect scrollRect;

    public enum SortMode
    {
        IP_ASC,
        IP_DESC,
        TRAFFIC_ASC,
        TRAFFIC_DESC,
        TYPE_ASC,
        TYPE_DESC
    }

    private SortMode currentSort = SortMode.IP_ASC;

    private Dictionary<string, List<int>> currentIPPortStats = new();
    private Dictionary<string, int> currentIPTrafficStats = new();
    private Dictionary<string, string> rememberedCountries = new();


    void Start()
    {
        StartCoroutine(UpdateIPList());
    }

    void Update()
    {
        if (Input.GetKeyDown(KeyCode.Tab))
        {
            Debug.Log("🔄 Tabキー押されました");
            CycleSortMode();
        }

        if (scrollRect != null)
        {
            float scrollSpeed = 0.2f; // ★ホイール感度
            float scrollInput = Input.GetAxis("Mouse ScrollWheel");

            if (Mathf.Abs(scrollInput) > 0.01f)
            {
                scrollRect.verticalNormalizedPosition += scrollInput * scrollSpeed;
                scrollRect.verticalNormalizedPosition = Mathf.Clamp01(scrollRect.verticalNormalizedPosition);
            }
        }
    }

    IEnumerator UpdateIPList()
    {
        while (true)
        {
            if (networkVisualizer != null && ipListText != null)
            {
                List<string> ips = networkVisualizer.GetCommunicatingIPs().ToList();

                // ソート処理
                switch (currentSort)
                {
                    case SortMode.IP_ASC:
                        ips.Sort();
                        break;
                    case SortMode.IP_DESC:
                        ips.Sort();
                        ips.Reverse();
                        break;
                    case SortMode.TRAFFIC_ASC:
                        ips.Sort((a, b) =>
                        {
                            int countA = currentIPTrafficStats.ContainsKey(a) ? currentIPTrafficStats[a] : 0;
                            int countB = currentIPTrafficStats.ContainsKey(b) ? currentIPTrafficStats[b] : 0;
                            return countA.CompareTo(countB);
                        });
                        break;
                    case SortMode.TRAFFIC_DESC:
                        ips.Sort((a, b) =>
                        {
                            int countA = currentIPTrafficStats.ContainsKey(a) ? currentIPTrafficStats[a] : 0;
                            int countB = currentIPTrafficStats.ContainsKey(b) ? currentIPTrafficStats[b] : 0;
                            return countB.CompareTo(countA);
                        });
                        break;
                    case SortMode.TYPE_ASC:
                        ips.Sort((a, b) => GetIPTypeOrder(a).CompareTo(GetIPTypeOrder(b)));
                        break;
                    case SortMode.TYPE_DESC:
                        ips.Sort((a, b) => GetIPTypeOrder(b).CompareTo(GetIPTypeOrder(a)));
                        break;
                }

                ipListText.text = $"【現在通信中のIP】[{currentSort}]\n";

                foreach (string ip in ips)
                {
                    string type = GetIPType(ip);
                    string country = rememberedCountries.ContainsKey(ip) ? rememberedCountries[ip] : "";

                    string line = $"{ip} ({type})";
                    if (!string.IsNullOrEmpty(country))
                    {
                        line += $" [{country}]";
                    }

                    if (currentIPPortStats.ContainsKey(ip) || currentIPTrafficStats.ContainsKey(ip))
                    {
                        line += " →";

                        if (currentIPPortStats.ContainsKey(ip))
                        {
                            List<int> ports = currentIPPortStats[ip];
                            line += $" 使用ポート: {string.Join(", ", ports)}";
                        }

                        if (currentIPTrafficStats.ContainsKey(ip))
                        {
                            int count = currentIPTrafficStats[ip];
                            line += $" 通信回数: {count}";
                        }
                    }

                    ipListText.text += line + "\n";
                }
            }

            yield return new WaitForSeconds(5f);
        }
    }


    void RefreshIPListNow()
    {
        StopAllCoroutines();
        StartCoroutine(UpdateIPList());
    }

    void CycleSortMode()
    {
        currentSort = currentSort switch
        {
            SortMode.IP_ASC => SortMode.IP_DESC,
            SortMode.IP_DESC => SortMode.TRAFFIC_ASC,
            SortMode.TRAFFIC_ASC => SortMode.TRAFFIC_DESC,
            SortMode.TRAFFIC_DESC => SortMode.TYPE_ASC,
            SortMode.TYPE_ASC => SortMode.TYPE_DESC,
            SortMode.TYPE_DESC => SortMode.IP_ASC,
            _ => SortMode.IP_ASC
        };

        RefreshIPListNow(); // 🔄 再描画
    }



    int GetIPTypeOrder(string ip)
    {
        string type = GetIPType(ip);
        return type switch
        {
            "プライベートIP" => 0,
            "マルチキャストIP" => 1,
            "インターネット" => 2,
            _ => 3
        };
    }

    string GetIPType(string ip)
    {
        if (ip.StartsWith("10.") ||
            ip.StartsWith("192.168.") ||
            (ip.StartsWith("172.") && int.TryParse(ip.Split('.')[1], out int second) && second >= 16 && second <= 31))
        {
            return "プライベートIP";
        }
        else if (ip.StartsWith("224.") || ip.StartsWith("239."))
        {
            return "マルチキャストIP";
        }
        else
        {
            return "インターネット";
        }
    }

    public void UpdateIPCountryStats(Dictionary<string, string> ipCountryStats)
    {
        foreach (var entry in ipCountryStats)
        {
            rememberedCountries[entry.Key] = entry.Value;
        }
    }


    public void UpdateIPPortStats(Dictionary<string, List<int>> ipPortStats)
    {
        currentIPPortStats = ipPortStats;
    }

    public void UpdateIPTrafficStats(Dictionary<string, int> ipTrafficStats)
    {
        currentIPTrafficStats = ipTrafficStats;
    }
}



