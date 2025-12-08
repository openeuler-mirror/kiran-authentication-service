#!/bin/bash

# 获取输入参数
FILE_NAME=$1
# 如果为空，则使用当前时间字符串为默认文件名
if [ -z "$FILE_NAME" ]; then
    FILE_NAME=$(date +%Y%m%d%H%M%S).mp4
fi
echo "screen recorder file name: $FILE_NAME"

# 获取屏幕分辨率
RESOLUTION=$(xdpyinfo | grep dimensions | awk '{print $2}')
echo "screen resolution: $RESOLUTION"

# 检查可用编码器
ENCODERS=$(ffmpeg -encoders 2>/dev/null)

# 默认 CPU 编码
CODEC="libx264"
EXTRA=""

if echo "$ENCODERS" | grep -q "h264_nvenc"; then
    CODEC="h264_nvenc"
    EXTRA="-preset fast -b:v 5M"
elif echo "$ENCODERS" | grep -q "h264_vaapi"; then
    CODEC="h264_vaapi"
    EXTRA="-vaapi_device /dev/dri/renderD128 -vf format=nv12,hwupload"
elif echo "$ENCODERS" | grep -q "h264_qsv"; then
    CODEC="h264_qsv"
    EXTRA=""
fi

echo "使用编码器: $CODEC"


# 执行录屏
CMD="ffmpeg -f x11grab -framerate 30 -video_size $RESOLUTION -i :0.0 $FILE_NAME -y"
#ffmpeg -f x11grab -framerate 30 -video_size $RESOLUTION -i :0.0 -c:v $CODEC $EXTRA output.mp4
echo "开始录屏: $CMD"
$CMD
