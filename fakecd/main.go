package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// 全局配置变量
var (
	serverPort          string
	authenticationToken string
	fileMutex           sync.Mutex                                    // 文件操作锁
	inputValidator      = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\/]+$`) // 防止Shell注入正则
)

// 请求结构体
type DeployRequest struct {
	ImageRepo string `json:"image"`
	NewTag    string `json:"tag"`
}

// 统一标准响应结构
type StandardResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// 成功时JSON返回
type SuccessData struct {
	UpdateImage string `json:"updateImage"`
	NewTag      string `json:"newTag"`
}

func main() {
	flag.StringVar(&serverPort, "port", "5000", "监听端口")
	flag.Parse()

	authenticationToken = os.Getenv("AUTH_TOKEN")
	if authenticationToken == "" {
		log.Fatal("Startup failed: Please set AUTH_TOKEN environment variable")
	}

	// 启动日志
	log.Println("FakeCD started")

	// 注册路由
	mux := http.NewServeMux()
	mux.HandleFunc("/deploy", authenticationMiddleware(handleDeploy))

	// 使用自定义Server设置超时
	server := &http.Server{
		Addr:         ":" + serverPort,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// 鉴权中间件
func authenticationMiddleware(nextHandler http.HandlerFunc) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, httpRequest *http.Request) {
		tokenHeader := httpRequest.Header.Get("Authorization")

		// 比对Token
		if subtle.ConstantTimeCompare([]byte(tokenHeader), []byte(authenticationToken)) != 1 {
			log.Printf("Auth failed: %s", httpRequest.RemoteAddr)
			sendJSONResponse(responseWriter, http.StatusUnauthorized, "Unauthorized", nil)
			return
		}

		nextHandler(responseWriter, httpRequest)
	}
}

// 统一发送JSON响应
func sendJSONResponse(responseWriter http.ResponseWriter, statusCode int, message string, data interface{}) {
	responseWriter.Header().Set("Content-Type", "application/json")

	// HTTP状态码
	responseWriter.WriteHeader(statusCode)

	// 构造响应体
	response := StandardResponse{
		Code:    statusCode,
		Message: message,
		Data:    data,
	}

	if err := json.NewEncoder(responseWriter).Encode(response); err != nil {
		log.Printf("Error sending JSON response: %v", err)
	}
}

// 处理部署请求的主逻辑
func handleDeploy(responseWriter http.ResponseWriter, httpRequest *http.Request) {
	if httpRequest.Method != http.MethodPost {
		sendJSONResponse(responseWriter, http.StatusMethodNotAllowed, "Method Not Allowed", nil)
		return
	}

	var deployRequest DeployRequest
	if err := json.NewDecoder(httpRequest.Body).Decode(&deployRequest); err != nil {
		sendJSONResponse(responseWriter, http.StatusBadRequest, "JSON parse error", nil)
		return
	}

	// 检查输入字符是否合法
	if !inputValidator.MatchString(deployRequest.ImageRepo) || !inputValidator.MatchString(deployRequest.NewTag) {
		sendJSONResponse(responseWriter, http.StatusBadRequest, "Invalid input characters", nil)
		return
	}

	fileMutex.Lock()
	defer fileMutex.Unlock()

	// 扫描并处理当前目录下的所有子文件夹
	totalMatched, actualUpdated, err := scanAndProcessAllDirectories(deployRequest.ImageRepo, deployRequest.NewTag)
	if err != nil {
		log.Printf("Process error: %v", err)
		sendJSONResponse(responseWriter, http.StatusInternalServerError, fmt.Sprintf("Process Error: %v", err), nil)
		return
	}

	// 不包含镜像
	if totalMatched == 0 {
		errorMessage := fmt.Sprintf("No service found using image '%s'", deployRequest.ImageRepo)
		log.Println("[Warn] " + errorMessage)
		sendJSONResponse(responseWriter, http.StatusNotFound, errorMessage, nil)
		return
	}

	// 构造成功响应数据
	responseData := SuccessData{
		UpdateImage: deployRequest.ImageRepo, // 返回传入的镜像名
		NewTag:      deployRequest.NewTag,    // 返回传入的Tag
	}

	// 找到镜像但Tag一样
	if actualUpdated == 0 {
		log.Printf("Image %s:%s matches %d projects, but already the latest version. Skipped.", deployRequest.ImageRepo, deployRequest.NewTag, totalMatched)
		sendJSONResponse(responseWriter, http.StatusOK, "Skipped", responseData)
		return
	}

	log.Printf("Successfully updated projects. Matched: %d, Updated: %d | Image: %s:%s", totalMatched, actualUpdated, deployRequest.ImageRepo, deployRequest.NewTag)
	sendJSONResponse(responseWriter, http.StatusOK, "Success", responseData)
}

// 扫描当前目录下的所有文件夹
func scanAndProcessAllDirectories(targetImageRepository, newTag string) (int, int, error) {
	matchedCount := 0
	updatedCount := 0

	// 读取当前目录下的文件列表
	entries, err := os.ReadDir(".")
	if err != nil {
		return 0, 0, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			directoryName := entry.Name()

			// 检查文件夹下是否有docker-compose
			composeFilePath := findComposeFileInDir(directoryName)
			if composeFilePath == "" {
				continue
			}

			// 读取指定YAML文件查找匹配的镜像并更新
			isMatched, isUpdated, err := processProjectUpdate(directoryName, composeFilePath, targetImageRepository, newTag)
			if err != nil {
				log.Printf("Error processing %s: %v", composeFilePath, err)
				return matchedCount, updatedCount, err
			}

			if isMatched {
				matchedCount++
			}

			if isUpdated {
				updatedCount++
			}
		}
	}

	return matchedCount, updatedCount, nil
}

// 在指定目录下寻找docker-compose文件
func findComposeFileInDir(dir string) string {
	pathYaml := filepath.Join(dir, "docker-compose.yaml")
	if _, err := os.Stat(pathYaml); err == nil {
		return pathYaml
	}

	pathYml := filepath.Join(dir, "docker-compose.yml")
	if _, err := os.Stat(pathYml); err == nil {
		return pathYml
	}

	return ""
}

// 防止注释丢失和格式错乱
func processProjectUpdate(workDir, filePath, targetImageRepo, newTag string) (bool, bool, error) {
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return false, false, err
	}

	var rootNode yaml.Node
	if err := yaml.Unmarshal(fileData, &rootNode); err != nil {
		return false, false, err
	}

	if len(rootNode.Content) == 0 {
		return false, false, nil
	}
	docNode := rootNode.Content[0]

	newFullImageString := fmt.Sprintf("%s:%s", targetImageRepo, newTag)
	foundTargetRepo := false
	needsUpdate := false

	var servicesNode *yaml.Node
	for i := 0; i < len(docNode.Content); i += 2 {
		if docNode.Content[i].Value == "services" {
			servicesNode = docNode.Content[i+1]
			break
		}
	}

	if servicesNode != nil {
		// 遍历所有服务
		for i := 0; i < len(servicesNode.Content); i += 2 {
			serviceConfig := servicesNode.Content[i+1]

			// 遍历查找imageName
			for j := 0; j < len(serviceConfig.Content); j += 2 {
				if serviceConfig.Content[j].Value == "image" {
					imageNode := serviceConfig.Content[j+1]
					currentImageStr := imageNode.Value

					if getRepositoryFromImage(currentImageStr) == targetImageRepo {
						foundTargetRepo = true
						if currentImageStr != newFullImageString {
							needsUpdate = true
							imageNode.Value = newFullImageString
						}
					}
					break
				}
			}
		}
	}

	// 镜像不存在
	if !foundTargetRepo {
		return false, false, nil
	}

	// 找到了镜像但是Tag一样
	if !needsUpdate {
		return true, false, nil
	}

	log.Printf("Project %s needs update to %s. Starting update sequence.", workDir, newTag)

	// Pull失败返回Error
	if err := runDockerPull(workDir, newFullImageString); err != nil {
		return true, false, fmt.Errorf("pull failed for %s: %v", newFullImageString, err)
	}

	// 写入文件时保留结构
	file, err := os.Create(filePath)
	if err != nil {
		return true, false, fmt.Errorf("create file failed: %v", err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2) // YAML标准缩进
	if err := encoder.Encode(&rootNode); err != nil {
		return true, false, fmt.Errorf("yaml encode failed: %v", err)
	}

	// 更新项目
	if err := runDockerUp(workDir, filePath); err != nil {
		return true, true, fmt.Errorf("docker up failed: %v", err)
	}

	log.Printf("Project %s updated successfully.", workDir)
	return true, true, nil
}

func getRepositoryFromImage(fullImageString string) string {
	lastColonIndex := strings.LastIndex(fullImageString, ":")
	if lastColonIndex == -1 {
		return fullImageString
	}
	return fullImageString[:lastColonIndex]
}

// 拉取镜像
func runDockerPull(workingDirectory, fullImage string) error {
	// 设置10分钟超时
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	log.Printf("Executing pull in %s: docker pull %s", workingDirectory, fullImage)

	cmd := exec.CommandContext(ctx, "docker", "pull", fullImage)
	cmd.Dir = workingDirectory
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// 更新项目
func runDockerUp(workingDirectory string, composeFilePath string) error {
	// 设置5分钟超时
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fileName := filepath.Base(composeFilePath)
	dockerArguments := []string{"compose", "-f", fileName, "up", "-d"}

	log.Printf("Executing up in %s: docker %v", workingDirectory, strings.Join(dockerArguments, " "))

	cmd := exec.CommandContext(ctx, "docker", dockerArguments...)
	cmd.Dir = workingDirectory
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}
