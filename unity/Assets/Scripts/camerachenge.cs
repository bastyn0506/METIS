using UnityEngine;

public class CameraSwitcher : MonoBehaviour
{
    public Camera mainCamera;
    public Camera uiCamera;

    private bool mainActive = true;

    void Start()
    {
        SetCamera(mainCamera, true);
        SetCamera(uiCamera, false);
        UpdateCursor(); // 起動時のカーソル状態
    }

    void Update()
    {
        if (Input.GetKeyDown(KeyCode.C))  // ← カメラ切り替えキー
        {
            mainActive = !mainActive;
            SetCamera(mainCamera, mainActive);
            SetCamera(uiCamera, !mainActive);
            UpdateCursor(); // 切り替え後のカーソル状態更新
        }
    }

    void SetCamera(Camera cam, bool enable)
    {
        cam.enabled = enable;
        AudioListener listener = cam.GetComponent<AudioListener>();
        if (listener) listener.enabled = enable;
    }

    void UpdateCursor()
    {
        if (mainActive)
        {
            Cursor.lockState = CursorLockMode.Locked; // 固定して非表示
            Cursor.visible = false;
        }
        else
        {
            Cursor.lockState = CursorLockMode.None;   // 自由にして表示
            Cursor.visible = true;
        }
    }
}


