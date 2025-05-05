using UnityEngine;

public class FreeCameraController : MonoBehaviour
{
    public float moveSpeed = 10f;
    public float lookSpeed = 2f;

    float yaw = 0f;
    float pitch = 0f;

    void Start()
    {
        Cursor.lockState = CursorLockMode.Locked;
    }

    void Update()
    {
        // éãì_ÇÃâÒì]
        yaw += lookSpeed * Input.GetAxis("Mouse X");
        pitch -= lookSpeed * Input.GetAxis("Mouse Y");
        pitch = Mathf.Clamp(pitch, -90f, 90f);
        transform.eulerAngles = new Vector3(pitch, yaw, 0f);

        // à⁄ìÆÇÃì¸óÕ
        float horizontal = Input.GetAxis("Horizontal"); // A/D
        float vertical = Input.GetAxis("Vertical");     // W/S

        Vector3 move = transform.right * horizontal + transform.forward * vertical;

        // è„è∏ÅEâ∫ç~
        if (Input.GetKey(KeyCode.Space))
        {
            move += transform.up; // è„è∏
        }
        if (Input.GetKey(KeyCode.LeftShift))
        {
            move -= transform.up; // â∫ç~
        }

        transform.position += move * moveSpeed * Time.deltaTime;
    }
}

