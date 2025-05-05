using UnityEngine;

public class NodeAppearEffect : MonoBehaviour
{
    public float appearDuration = 0.5f;
    public AnimationCurve scaleCurve;

    private Vector3 originalScale;
    private float timer = 0f;

    void Start()
    {
        originalScale = transform.localScale;
        transform.localScale = Vector3.zero;
    }

    void Update()
    {
        if (timer < appearDuration)
        {
            timer += Time.deltaTime;
            float t = Mathf.Clamp01(timer / appearDuration);
            float scaleValue = scaleCurve.Evaluate(t);
            transform.localScale = originalScale * scaleValue;
        }
    }
}

