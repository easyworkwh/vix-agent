说明：
pyvix-module是对vix api中，参考vix.h和vm_basic_types.h实现翻译过来的python类的接口封装。
使得python程序可以调用vix api对虚拟资源进行控制。
环境要求：
推荐安装VMware VIX API 1.11.0，安装完毕后，请找到其内包含的Workstation-8.0.0-and-vSphere-5.0.0目录下的动态库文件vix.dll或libvix.so，它将是被python load的对象文件，同时需要使得该目录位于系统环境变量PATH中。