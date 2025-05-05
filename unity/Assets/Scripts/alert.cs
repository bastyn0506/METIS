using UnityEngine;
using UnityEngine.UI;
using System.Collections;

public class AlertEffectManager : MonoBehaviour
{
    public Light alertLight;              // 点滅用ライト（通常はOFF）
    public Image alertPanel;              // UI警告パネル（赤フラッシュ）
    public AudioSource audioSource;       // ブザー音を鳴らす
    public AudioClip alertSound;          // ブザーの音素材

    public float alertCooldown = 10f;     // クールダウン時間（秒）
    private float lastAlertTime = -9999f; // 最後に鳴った時刻

    void Start()
    {
        // 初期化：ライトとパネルをOFFにする
        if (alertLight != null) alertLight.intensity = 0f;
        if (alertPanel != null) alertPanel.color = new Color(1, 0, 0, 0f); // 完全透明
    }

    public void TriggerAlert()
    {
        float now = Time.time;

        if (now - lastAlertTime < alertCooldown)
        {
            Debug.Log($"⏳ クールダウン中 ({(alertCooldown - (now - lastAlertTime)).ToString("F1")} 秒残り) → ブザー再生スキップ");
            return;
        }

        lastAlertTime = now;
        Debug.Log("🔴 TriggerAlert() が呼ばれました");
        StartCoroutine(DoAlertEffects());
    }

    private IEnumerator DoAlertEffects()
    {
        Debug.Log("🚨 点滅コルーチン開始");

        for (int i = 0; i < 8; i++)
        {
            // ライトとパネル ON
            if (alertLight != null)
            {
                alertLight.intensity = 5f;
                Debug.Log("💡 ライトON");
            }

            if (alertPanel != null)
            {
                alertPanel.color = new Color(1, 0, 0, 0.5f); // 半透明赤
                Debug.Log("🟥 パネルON");
            }

            if (audioSource != null && alertSound != null)
            {
                audioSource.PlayOneShot(alertSound);
                Debug.Log("🔊 ブザー再生");
            }

            yield return new WaitForSeconds(0.2f);

            // OFF処理
            if (alertLight != null) alertLight.intensity = 0f;
            if (alertPanel != null) alertPanel.color = new Color(1, 0, 0, 0f); // 完全透明

            Debug.Log("💡 ライトOFF / 🟥 パネルOFF");

            yield return new WaitForSeconds(0.2f);
        }

        Debug.Log("✅ 点滅終了");
    }
}







