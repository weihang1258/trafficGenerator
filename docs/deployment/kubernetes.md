# Kubernetes 部署指南

本文档介绍如何在 Kubernetes 集群中部署 Traffic Generator。

## 目录

1. [前置要求](#前置要求)
2. [快速开始](#快速开始)
3. [配置说明](#配置说明)
4. [部署验证](#部署验证)
5. [服务管理](#服务管理)
6. [扩容缩容](#扩容缩容)
7. [监控配置](#监控配置)
8. [故障排查](#故障排查)

---

## 前置要求

### 软件要求

| 软件 | 版本要求 | 检查命令 |
|------|---------|---------|
| Kubernetes | >= 1.25 | `kubectl version` |
| kubectl | >= 1.25 | `kubectl version` |
| Helm (可选) | >= 3.0 | `helm version` |

### 集群要求

- 至少 3 个节点
- 每个节点至少 4 CPU, 8GB 内存
- 支持 LoadBalancer 或 Ingress
- 动态存储供应（可选）

### 权限要求

- 创建/删除 Namespace
- 创建/删除 Deployment, Service, ConfigMap, Secret
- 创建/删除 Ingress
- 配置 RBAC（可选）

---

## 快速开始

### 1. 克隆代码

```bash
git clone https://github.com/your-org/traffic-generator.git
cd traffic-generator/trafficgen
```

### 2. 创建命名空间

```bash
kubectl create namespace trafficgen
```

### 3. 创建 Secret

```bash
# 生成随机密码
JWT_SECRET=$(openssl rand -base64 32)
DB_PASSWORD=$(openssl rand -base64 16)

# 创建 Secret
kubectl create secret generic trafficgen-secret \
  --from-literal=jwt-secret=$JWT_SECRET \
  --from-literal=db-password=$DB_PASSWORD \
  -n trafficgen
```

### 4. 创建 ConfigMap

```bash
kubectl apply -f deployments/k8s/configmap.yaml -n trafficgen
```

### 5. 部署应用

```bash
# 部署所有资源
kubectl apply -f deployments/k8s/ -n trafficgen

# 或逐个部署
kubectl apply -f deployments/k8s/secret.yaml -n trafficgen
kubectl apply -f deployments/k8s/configmap.yaml -n trafficgen
kubectl apply -f deployments/k8s/deployment.yaml -n trafficgen
kubectl apply -f deployments/k8s/service.yaml -n trafficgen
kubectl apply -f deployments/k8s/hpa.yaml -n trafficgen
kubectl apply -f deployments/k8s/ingress.yaml -n trafficgen
```

### 6. 验证部署

```bash
# 查看 Pod 状态
kubectl get pods -n trafficgen

# 查看服务状态
kubectl get services -n trafficgen

# 查看 Ingress
kubectl get ingress -n trafficgen

# 查看日志
kubectl logs -f deployment/trafficgen -n trafficgen
```

---

## 配置说明

### Deployment 配置

编辑 `deployments/k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: trafficgen
  namespace: trafficgen
spec:
  replicas: 2
  selector:
    matchLabels:
      app: trafficgen
  template:
    metadata:
      labels:
        app: trafficgen
    spec:
      containers:
      - name: trafficgen
        image: trafficgen:latest
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8080
        resources:
          limits:
            cpu: "4"
            memory: "8Gi"
          requests:
            cpu: "2"
            memory: "4Gi"
        env:
        - name: TRAFFICGEN_DATABASE_DSN
          valueFrom:
            secretKeyRef:
              name: trafficgen-secret
              key: db-dsn
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
        - name: data
          mountPath: /data
      volumes:
      - name: config
        configMap:
          name: trafficgen-config
      - name: data
        emptyDir: {}
```

### Service 配置

编辑 `deployments/k8s/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: trafficgen-service
  namespace: trafficgen
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: 8080
  selector:
    app: trafficgen
```

### ConfigMap 配置

编辑 `deployments/k8s/configmap.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: trafficgen-config
  namespace: trafficgen
data:
  config.yaml: |
    server:
      host: "0.0.0.0"
      port: 8080
    database:
      type: "postgres"
      dsn: "host=postgres port=5432 user=trafficgen password=secret dbname=trafficgen sslmode=disable"
    engine:
      config_workers: 4
      packet_workers: 8
      output_workers: 4
```

### Secret 配置

创建 Secret:

```bash
# 从文件创建
kubectl create secret generic trafficgen-secret \
  --from-file=config.yaml=path/to/config.yaml \
  -n trafficgen

# 从字面值创建
kubectl create secret generic trafficgen-secret \
  --from-literal=jwt-secret=your-jwt-secret \
  --from-literal=db-password=your-db-password \
  -n trafficgen
```

### Ingress 配置

编辑 `deployments/k8s/ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: trafficgen-ingress
  namespace: trafficgen
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - trafficgen.example.com
    secretName: trafficgen-tls
  rules:
  - host: trafficgen.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: trafficgen-service
            port:
              number: 8080
```

---

## 部署验证

### 检查 Pod 状态

```bash
# 查看 Pod 列表
kubectl get pods -n trafficgen

# 查看 Pod 详情
kubectl describe pod <pod-name> -n trafficgen

# 查看 Pod 日志
kubectl logs <pod-name> -n trafficgen

# 实时查看日志
kubectl logs -f <pod-name> -n trafficgen
```

### 检查服务状态

```bash
# 查看服务列表
kubectl get services -n trafficgen

# 查看服务详情
kubectl describe service trafficgen-service -n trafficgen

# 查看端点
kubectl get endpoints -n trafficgen
```

### 测试服务访问

```bash
# 端口转发
kubectl port-forward svc/trafficgen-service 8080:8080 -n trafficgen

# 健康检查
curl http://localhost:8080/health

# 查看指标
curl http://localhost:8080/metrics
```

---

## 服务管理

### 更新应用

```bash
# 更新镜像
kubectl set image deployment/trafficgen trafficgen=trafficgen:v2.0.0 -n trafficgen

# 查看更新状态
kubectl rollout status deployment/trafficgen -n trafficgen

# 查看更新历史
kubectl rollout history deployment/trafficgen -n trafficgen
```

### 回滚应用

```bash
# 回滚到上一个版本
kubectl rollout undo deployment/trafficgen -n trafficgen

# 回滚到指定版本
kubectl rollout undo deployment/trafficgen --to-revision=2 -n trafficgen

# 查看回滚状态
kubectl rollout status deployment/trafficgen -n trafficgen
```

### 重启应用

```bash
# 重启 Deployment
kubectl rollout restart deployment/trafficgen -n trafficgen

# 查看重启状态
kubectl rollout status deployment/trafficgen -n trafficgen
```

### 扩容缩容

```bash
# 手动扩容
kubectl scale deployment/trafficgen --replicas=5 -n trafficgen

# 查看 Pod 数量
kubectl get pods -n trafficgen
```

---

## 扩容缩容

### 手动扩容

```bash
# 扩容到 5 个副本
kubectl scale deployment/trafficgen --replicas=5 -n trafficgen

# 缩容到 2 个副本
kubectl scale deployment/trafficgen --replicas=2 -n trafficgen
```

### 自动扩容 (HPA)

编辑 `deployments/k8s/hpa.yaml`:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: trafficgen-hpa
  namespace: trafficgen
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: trafficgen
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

应用 HPA 配置:

```bash
# 应用 HPA
kubectl apply -f deployments/k8s/hpa.yaml -n trafficgen

# 查看 HPA 状态
kubectl get hpa -n trafficgen

# 查看 HPA 详情
kubectl describe hpa trafficgen-hpa -n trafficgen
```

---

## 监控配置

### Prometheus 部署

```bash
# 部署 Prometheus
kubectl apply -f deployments/k8s/prometheus.yaml -n trafficgen

# 查看 Prometheus 状态
kubectl get pods -n trafficgen -l app=prometheus

# 访问 Prometheus UI
kubectl port-forward svc/prometheus-service 9090:9090 -n trafficgen
```

### Grafana 部署

```bash
# 部署 Grafana
kubectl apply -f deployments/k8s/grafana.yaml -n trafficgen

# 查看 Grafana 状态
kubectl get pods -n trafficgen -l app=grafana

# 访问 Grafana UI
kubectl port-forward svc/grafana-service 3000:3000 -n trafficgen
```

### 配置监控

1. **Prometheus ServiceMonitor**

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: trafficgen-monitor
  namespace: trafficgen
spec:
  selector:
    matchLabels:
      app: trafficgen
  endpoints:
  - port: http
    path: /metrics
    interval: 10s
```

2. **Grafana Dashboard ConfigMap**

```bash
# 创建 Dashboard ConfigMap
kubectl create configmap grafana-dashboard \
  --from-file=dashboard.json=deployments/grafana/dashboard.json \
  -n trafficgen
```

---

## 故障排查

### Pod 无法启动

**排查步骤**:

```bash
# 查看 Pod 状态
kubectl get pods -n trafficgen

# 查看 Pod 事件
kubectl describe pod <pod-name> -n trafficgen

# 查看容器日志
kubectl logs <pod-name> -n trafficgen

# 查看上一个容器的日志（如果重启了）
kubectl logs <pod-name> --previous -n trafficgen
```

**常见原因**:
- 镜像拉取失败
- 资源不足
- 配置错误
- 权限问题

### 服务无法访问

**排查步骤**:

```bash
# 查看服务状态
kubectl get services -n trafficgen

# 查看端点
kubectl get endpoints -n trafficgen

# 查看 Ingress
kubectl get ingress -n trafficgen

# 测试服务连接
kubectl run test --image=busybox --rm -it -- wget -O- http://trafficgen-service:8080/health
```

### 性能问题

**排查步骤**:

```bash
# 查看资源使用
kubectl top pods -n trafficgen
kubectl top nodes

# 查看资源限制
kubectl describe pod <pod-name> -n trafficgen | grep -A 5 "Limits:"

# 查看事件
kubectl get events -n trafficgen --sort-by='.lastTimestamp'
```

---

## 高级配置

### 持久化存储

使用 PersistentVolume 存储数据:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: trafficgen-pvc
  namespace: trafficgen
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: standard
```

在 Deployment 中挂载:

```yaml
spec:
  template:
    spec:
      containers:
      - name: trafficgen
        volumeMounts:
        - name: data
          mountPath: /data
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: trafficgen-pvc
```

### 配置 RBAC

创建 ServiceAccount 和 RBAC:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: trafficgen-sa
  namespace: trafficgen
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: trafficgen-role
  namespace: trafficgen
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: trafficgen-rolebinding
  namespace: trafficgen
subjects:
- kind: ServiceAccount
  name: trafficgen-sa
  namespace: trafficgen
roleRef:
  kind: Role
  name: trafficgen-role
  apiGroup: rbac.authorization.k8s.io
```

### Pod 安全策略

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: trafficgen-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'persistentVolumeClaim'
    - 'secret'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

---

## 生产环境建议

### 高可用配置

1. **多副本部署**
   ```yaml
   spec:
     replicas: 3
   ```

2. **Pod 反亲和性**
   ```yaml
   affinity:
     podAntiAffinity:
       preferredDuringSchedulingIgnoredDuringExecution:
       - weight: 100
         podAffinityTerm:
           labelSelector:
             matchExpressions:
             - key: app
               operator: In
               values:
               - trafficgen
           topologyKey: kubernetes.io/hostname
   ```

3. **Pod 中断预算**
   ```yaml
   apiVersion: policy/v1
   kind: PodDisruptionBudget
   metadata:
     name: trafficgen-pdb
     namespace: trafficgen
   spec:
     minAvailable: 2
     selector:
       matchLabels:
         app: trafficgen
   ```

### 安全配置

1. **使用 Secret 存储敏感信息**
2. **启用 NetworkPolicy**
3. **配置 ResourceQuota**
4. **启用 Pod Security Policy**

### 监控告警

1. **部署 Prometheus + Grafana**
2. **配置告警规则**
3. **集成 AlertManager**

---

## 常用命令速查

```bash
# 部署应用
kubectl apply -f deployments/k8s/ -n trafficgen

# 查看状态
kubectl get all -n trafficgen

# 查看日志
kubectl logs -f deployment/trafficgen -n trafficgen

# 端口转发
kubectl port-forward svc/trafficgen-service 8080:8080 -n trafficgen

# 扩容
kubectl scale deployment/trafficgen --replicas=5 -n trafficgen

# 更新镜像
kubectl set image deployment/trafficgen trafficgen=trafficgen:v2.0.0 -n trafficgen

# 回滚
kubectl rollout undo deployment/trafficgen -n trafficgen

# 删除部署
kubectl delete -f deployments/k8s/ -n trafficgen
```

---

## 参考链接

- [Kubernetes 官方文档](https://kubernetes.io/docs/)
- [kubectl 命令参考](https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands)
- [Kubernetes 最佳实践](https://kubernetes.io/docs/concepts/configuration/overview/)
