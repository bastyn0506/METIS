using UnityEngine;
using System.Collections.Generic;
using System.Collections;
using TMPro;
using System.Net;

public class NetworkVisualizer : MonoBehaviour
{
    public GameObject nodePrefab;           // ノードプレハブ
    public Material lineMaterial;           // 線マテリアル（任意）
    public GameObject nodeEffectPrefab;     // ノード生成時のエフェクト
    public GameObject packetEffectPrefab;   // 通信パケットのエフェクト
    public GameObject centerNodePrefab;



    public float radius = 10f;              // 円配置の半径

    private Dictionary<string, GameObject> nodes = new Dictionary<string, GameObject>();
    private int peripheralIndex = 0;        // 外周ノードのカウント
    private string centerIP;                // 自PCのIPアドレス
    private HashSet<string> communicatingIPs = new HashSet<string>();
    private AudioSource alertAudio;
    private Dictionary<string, float> lastCommunicationTime = new Dictionary<string, float>();// IPペアごとの最終通信時刻を記録する
    public float communicationTimeout = 15f;// 何秒通信がなければ演出を止めるか（秒）
    private Dictionary<string, float> livePacketTimestamps = new Dictionary<string, float>();





    void Start()
    {
        // 自分のIPアドレスを取得して中心ノードとして登録
        centerIP = GetLocalIPAddress();
        Debug.Log("Local IP: " + centerIP);
        CreateNode(centerIP, Vector3.zero, "TCP", 700, "Japan"); // ← 第5引数に国名！

        AddConnection("192.168.1.10", centerIP, "Japan", "Japan", "TCP", 500);
        AddConnection("192.168.1.11", centerIP, "Japan", "Japan", "TCP", 500);
        AddConnection("192.168.1.12", centerIP, "Japan", "Japan", "TCP", 500);

        alertAudio = GetComponent<AudioSource>();

    }

    public void TriggerScanAlert(string ip)
    {
        if (nodes.ContainsKey(ip))
        {
            var node = nodes[ip];
            var renderer = node.GetComponent<Renderer>();

            if (renderer != null)
            {
                StartCoroutine(FlashRed(renderer));
            }

            if (alertAudio != null && !alertAudio.isPlaying)
            {
                alertAudio.Play();
            }

        }
    }




    private System.Collections.IEnumerator FlashRed(Renderer renderer)
    {
        Color originalColor = renderer.material.color;
        Color alertColor = Color.red;

        float flashDuration = 0.5f;

        for (int i = 0; i < 6; i++) // 3秒間点滅（0.5秒×6）
        {
            renderer.material.color = (i % 2 == 0) ? alertColor : originalColor;
            yield return new WaitForSeconds(flashDuration);
        }

        renderer.material.color = originalColor; // 最後は元に戻す
    }


    public void AddConnection(string src, string dst, string srcCountry = "", string dstCountry = "", string protocol = "Other", int size = 500)
    {
        GameObject srcNode = GetOrCreateNode(src, protocol, size, srcCountry);
        GameObject dstNode = GetOrCreateNode(dst, protocol, size, dstCountry);


        // 新しい通信IPを保存
        communicatingIPs.Add(src);
        communicatingIPs.Add(dst);

        string connectionKey = $"{src}_{dst}";

        void SendPacket() // 登録するローカル関数
        {
            if (srcNode && dstNode)
            {
                if (lastCommunicationTime.ContainsKey(connectionKey))
                    lastCommunicationTime[connectionKey] = Time.time;
                else
                    lastCommunicationTime.Add(connectionKey, Time.time);

                SendPacketVisual(srcNode.transform.position, dstNode.transform.position);
            }
        }

        StartCoroutine(RegisterRepeatingSender($"SendPacket_{src}_{dst}", SendPacket));// 動的にメソッド登録する（ラムダ式を対応させるため）
    }

    private Dictionary<string, System.Action> repeatingActions = new Dictionary<string, System.Action>();

    System.Collections.IEnumerator RegisterRepeatingSender(string methodName, System.Action action)
    {
        repeatingActions[methodName] = action;

        while (true)
        {
            yield return new WaitForSeconds(1f);
            if (!repeatingActions.ContainsKey(methodName))
                yield break;

            if (lastCommunicationTime.ContainsKey(methodName))
            {
                float elapsed = Time.time - lastCommunicationTime[methodName];
                if (elapsed > communicationTimeout)
                {
                    Debug.Log($"[停止] {methodName} は通信が {elapsed:F1} 秒途絶えたので停止");
                    repeatingActions.Remove(methodName);
                    lastCommunicationTime.Remove(methodName);
                    yield break; // コルーチン停止！
                }
            }

            repeatingActions[methodName]?.Invoke();
        }
    }

    System.Collections.IEnumerator RepeatLivePacket(string connectionKey, string src, string dst)
    {
        while (true)
        {
            yield return new WaitForSeconds(1f);

            if (!livePacketTimestamps.ContainsKey(connectionKey))
                yield break;

            float elapsed = Time.time - livePacketTimestamps[connectionKey];
            if (elapsed > communicationTimeout)
            {
                Debug.Log($"[停止] {connectionKey} 通信途絶でパケット停止");
                livePacketTimestamps.Remove(connectionKey);
                yield break;
            }

            if (nodes.ContainsKey(src) && nodes.ContainsKey(dst))
            {
                SendPacketVisual(nodes[src].transform.position, nodes[dst].transform.position);
            }
        }
    }



    GameObject GetOrCreateNode(string ip, string protocol, int size, string country = "")
    {
        if (nodes.ContainsKey(ip)) return nodes[ip];

        Vector3 pos = ip == centerIP ? Vector3.zero : GetNodePosition(peripheralIndex++);
        return CreateNode(ip, pos, protocol, size, country);
    }


    GameObject CreateNode(string ip, Vector3 position, string protocol, int size, string country = "")

    {
        GameObject prefabToUse = (ip == centerIP) ? centerNodePrefab : nodePrefab;
        GameObject node = Instantiate(prefabToUse, position, Quaternion.identity);

        node.name = ip;

        // IPアドレス表示
        TextMeshPro text = node.GetComponentInChildren<TextMeshPro>();
        if (text != null)
        {
            text.text = string.IsNullOrEmpty(country) ? ip : $"{ip}\n({country})";
        }

        else Debug.LogWarning("TextMeshProが見つかりません: " + ip);

        // サイズ調整
        float scale = Mathf.Clamp(size / 500f, 0.5f, 2.0f);
        node.transform.localScale = Vector3.one * scale;

        Renderer renderer = node.GetComponent<Renderer>();
        if (renderer != null)
        {
            if (protocol == "TCP") renderer.material.color = Color.red;
            else if (protocol == "UDP") renderer.material.color = Color.blue;
            else renderer.material.color = Color.green;
        }


        // ノード生成エフェクト
        if (nodeEffectPrefab != null)
        {
            GameObject effect = Instantiate(nodeEffectPrefab, position, Quaternion.identity);
            Destroy(effect, 2f);
        }

        nodes[ip] = node;
        return node;
    }

    Vector3 GetNodePosition(int index)
    {
        int nodesPerRing = 12;      // 1リングに何個並べるか（例: 12個）
        float baseRadius = 10f;      // 最初のリング半径
        float ringSpacing = 5f;      // リングごとの半径の増加量

        int ringIndex = index / nodesPerRing;           // 第何リングか
        int indexInRing = index % nodesPerRing;          // リング内での位置

        float angle = (360f / nodesPerRing) * indexInRing;
        float radius = baseRadius + ringSpacing * ringIndex;

        float x = Mathf.Cos(angle * Mathf.Deg2Rad) * radius;
        float z = Mathf.Sin(angle * Mathf.Deg2Rad) * radius;

        return new Vector3(x, 0, z);
    }


    // --- 通信パケットを飛ばす ---
    void SendPacketVisual(Vector3 start, Vector3 end)
    {
        if (packetEffectPrefab == null) return;

        GameObject packet = Instantiate(packetEffectPrefab, start, Quaternion.identity);
        StartCoroutine(MovePacket(packet, start, end));
    }

    System.Collections.IEnumerator MovePacket(GameObject packet, Vector3 start, Vector3 end)
    {
        float duration = 4.0f;
        float elapsed = 0f;

        // 中間点（放物線の高さ）
        Vector3 middle = (start + end) / 2f;
        middle += Vector3.up * 20f;  // 高さ調整（ここが軌道の山）

        while (elapsed < duration)
        {
            float t = elapsed / duration;

            // 2段階補間（start→middle→end）
            Vector3 a = Vector3.Lerp(start, middle, t);
            Vector3 b = Vector3.Lerp(middle, end, t);
            packet.transform.position = Vector3.Lerp(a, b, t);

            elapsed += Time.deltaTime;
            yield return null;
        }

        packet.transform.position = end;
        Destroy(packet);
    }

    public HashSet<string> GetCommunicatingIPs()
    {
        return communicatingIPs;
    }



    // --- IP取得 ---
    string GetLocalIPAddress()
    {
        string localIP = "127.0.0.1";
        foreach (var addr in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
        {
            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                localIP = addr.ToString();
                break;
            }
        }
        return localIP;
    }
}




