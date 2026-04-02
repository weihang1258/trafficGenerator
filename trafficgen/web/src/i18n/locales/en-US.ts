export default {
  // Common
  common: {
    confirm: 'Confirm',
    cancel: 'Cancel',
    save: 'Save',
    delete: 'Delete',
    edit: 'Edit',
    create: 'Create',
    search: 'Search',
    reset: 'Reset',
    refresh: 'Refresh',
    submit: 'Submit',
    back: 'Back',
    loading: 'Loading...',
    success: 'Success',
    error: 'Error',
    warning: 'Warning',
    info: 'Info',
    yes: 'Yes',
    no: 'No',
    enable: 'Enable',
    disable: 'Disable',
    status: 'Status',
    action: 'Action',
    detail: 'Detail',
    name: 'Name',
    description: 'Description',
    type: 'Type',
    time: 'Time',
    total: 'Total',
    page: 'Page',
    pageSize: 'Page Size',
    noData: 'No Data'
  },

  // Navigation Menu
  menu: {
    dashboard: 'Dashboard',
    taskManagement: 'Task Management',
    taskList: 'Task List',
    createTask: 'Create Task',
    strategyManagement: 'Strategy Management',
    interfaceManagement: 'Interface Management',
    history: 'History',
    settings: 'Settings',
    userManagement: 'User Management'
  },

  // Login Page
  login: {
    title: 'Traffic Generator',
    subtitle: 'High-Performance Network Traffic Generator',
    username: 'Username',
    password: 'Password',
    rememberMe: 'Remember Me',
    login: 'Login',
    logout: 'Logout',
    usernamePlaceholder: 'Please enter username',
    passwordPlaceholder: 'Please enter password',
    loginSuccess: 'Login successful',
    loginFailed: 'Login failed',
    pleaseInputUsername: 'Please enter username',
    pleaseInputPassword: 'Please enter password'
  },

  // Dashboard
  dashboard: {
    title: 'Dashboard',
    systemOverview: 'System Overview',
    activeTasks: 'Active Tasks',
    packetsSent: 'Packets Sent',
    throughput: 'Throughput',
    bufferUsage: 'Buffer Usage',
    recentTasks: 'Recent Tasks',
    taskDistribution: 'Task Distribution',
    protocolDistribution: 'Protocol Distribution',
    performanceMetrics: 'Performance Metrics'
  },

  // Task Management
  task: {
    title: 'Task List',
    createTask: 'Create Task',
    taskName: 'Task Name',
    protocol: 'Protocol',
    config: 'Config',
    output: 'Output',
    status: 'Status',
    createdAt: 'Created At',
    updatedAt: 'Updated At',
    startedAt: 'Started At',
    completedAt: 'Completed At',
    pending: 'Pending',
    running: 'Running',
    completed: 'Completed',
    failed: 'Failed',
    stopped: 'Stopped',
    start: 'Start',
    stop: 'Stop',
    delete: 'Delete',
    viewDetail: 'View Detail',
    taskDetail: 'Task Detail',
    basicInfo: 'Basic Info',
    statistics: 'Statistics',
    packets: 'Packets',
    bytes: 'Bytes',
    duration: 'Duration',
    rate: 'Rate',
    noTasks: 'No tasks',
    confirmDelete: 'Are you sure to delete this task?',
    confirmStart: 'Are you sure to start this task?',
    confirmStop: 'Are you sure to stop this task?',
    createSuccess: 'Task created successfully',
    createFailed: 'Failed to create task',
    startSuccess: 'Task started successfully',
    startFailed: 'Failed to start task',
    stopSuccess: 'Task stopped successfully',
    stopFailed: 'Failed to stop task',
    deleteSuccess: 'Task deleted successfully',
    deleteFailed: 'Failed to delete task'
  },

  // Task Create
  taskCreate: {
    title: 'Create Task',
    basicConfig: 'Basic Config',
    networkConfig: 'Network Config',
    outputConfig: 'Output Config',
    taskName: 'Task Name',
    taskNamePlaceholder: 'Please enter task name',
    protocol: 'Protocol',
    selectProtocol: 'Select Protocol',
    srcIP: 'Source IP',
    srcIPPlaceholder: 'Please enter source IP',
    dstIP: 'Destination IP',
    dstIPPlaceholder: 'Please enter destination IP',
    srcPort: 'Source Port',
    srcPortPlaceholder: 'Please enter source port',
    dstPort: 'Destination Port',
    dstPortPlaceholder: 'Please enter destination port',
    outputMode: 'Output Mode',
    selectOutputMode: 'Select Output Mode',
    interface: 'Interface',
    selectInterface: 'Select Interface',
    filename: 'Filename',
    filenamePlaceholder: 'Please enter filename',
    create: 'Create',
    cancel: 'Cancel',
    validation: {
      taskNameRequired: 'Please enter task name',
      protocolRequired: 'Please select protocol',
      srcIPRequired: 'Please enter source IP',
      srcIPInvalid: 'Invalid source IP format',
      dstIPRequired: 'Please enter destination IP',
      dstIPInvalid: 'Invalid destination IP format',
      srcPortRequired: 'Please enter source port',
      srcPortRange: 'Source port must be between 1-65535',
      dstPortRequired: 'Please enter destination port',
      dstPortRange: 'Destination port must be between 1-65535'
    }
  },

  // Strategy Management
  strategy: {
    title: 'Strategy Management',
    createStrategy: 'Create Strategy',
    strategyName: 'Strategy Name',
    strategyNamePlaceholder: 'Please enter strategy name',
    description: 'Description',
    descriptionPlaceholder: 'Please enter description',
    config: 'Config',
    noStrategies: 'No strategies',
    confirmDelete: 'Are you sure to delete this strategy?',
    createSuccess: 'Strategy created successfully',
    createFailed: 'Failed to create strategy',
    updateSuccess: 'Strategy updated successfully',
    updateFailed: 'Failed to update strategy',
    deleteSuccess: 'Strategy deleted successfully',
    deleteFailed: 'Failed to delete strategy'
  },

  // Interface Management
  interface: {
    title: 'Interface Management',
    interfaceName: 'Interface Name',
    macAddress: 'MAC Address',
    ipAddress: 'IP Address',
    netmask: 'Netmask',
    mtu: 'MTU',
    status: 'Status',
    up: 'Up',
    down: 'Down',
    linkUp: 'Link Up',
    linkDown: 'Link Down',
    refresh: 'Refresh',
    refreshSuccess: 'Refresh successful',
    refreshFailed: 'Refresh failed',
    noInterfaces: 'No interfaces'
  },

  // History
  history: {
    title: 'History',
    taskName: 'Task Name',
    protocol: 'Protocol',
    status: 'Status',
    startTime: 'Start Time',
    endTime: 'End Time',
    duration: 'Duration',
    packets: 'Packets',
    bytes: 'Bytes',
    export: 'Export',
    timeRange: 'Time Range',
    selectTimeRange: 'Select Time Range',
    today: 'Today',
    yesterday: 'Yesterday',
    last7Days: 'Last 7 Days',
    last30Days: 'Last 30 Days',
    custom: 'Custom',
    noHistory: 'No history'
  },

  // Settings
  settings: {
    title: 'Settings',
    basicSettings: 'Basic Settings',
    performanceSettings: 'Performance Settings',
    logSettings: 'Log Settings',
    language: 'Language',
    selectLanguage: 'Select Language',
    logLevel: 'Log Level',
    selectLogLevel: 'Select Log Level',
    debug: 'Debug',
    info: 'Info',
    warn: 'Warning',
    error: 'Error',
    maxTasks: 'Max Tasks',
    bufferSize: 'Buffer Size',
    workerCount: 'Worker Count',
    save: 'Save',
    reset: 'Reset',
    saveSuccess: 'Settings saved successfully',
    saveFailed: 'Failed to save settings',
    resetSuccess: 'Settings reset successfully',
    resetFailed: 'Failed to reset settings'
  },

  // User Management
  user: {
    title: 'User Management',
    createUser: 'Create User',
    username: 'Username',
    usernamePlaceholder: 'Please enter username',
    email: 'Email',
    emailPlaceholder: 'Please enter email',
    password: 'Password',
    passwordPlaceholder: 'Please enter password',
    role: 'Role',
    selectRole: 'Select Role',
    admin: 'Admin',
    user: 'User',
    guest: 'Guest',
    status: 'Status',
    active: 'Active',
    disabled: 'Disabled',
    createdAt: 'Created At',
    lastLogin: 'Last Login',
    resetPassword: 'Reset Password',
    confirmResetPassword: 'Are you sure to reset password for this user?',
    confirmDelete: 'Are you sure to delete this user?',
    createSuccess: 'User created successfully',
    createFailed: 'Failed to create user',
    updateSuccess: 'User updated successfully',
    updateFailed: 'Failed to update user',
    deleteSuccess: 'User deleted successfully',
    deleteFailed: 'Failed to delete user',
    resetPasswordSuccess: 'Password reset successfully',
    resetPasswordFailed: 'Failed to reset password',
    noUsers: 'No users'
  },

  // Protocol
  protocol: {
    tcp: 'TCP',
    udp: 'UDP',
    http: 'HTTP',
    dns: 'DNS',
    icmp: 'ICMP',
    arp: 'ARP'
  },

  // Output Mode
  outputMode: {
    interface: 'Interface Output',
    pcap: 'PCAP File',
    null: 'Statistics Only'
  },

  // Units
  unit: {
    packets: 'packets',
    bytes: 'bytes',
    bps: 'bps',
    kbps: 'Kbps',
    mbps: 'Mbps',
    gbps: 'Gbps',
    seconds: 'seconds',
    minutes: 'minutes',
    hours: 'hours',
    days: 'days'
  },

  // Error Messages
  error: {
    networkError: 'Network error',
    serverError: 'Server error',
    unauthorized: 'Unauthorized, please login again',
    forbidden: 'Forbidden',
    notFound: 'Resource not found',
    validationError: 'Validation failed',
    unknownError: 'Unknown error'
  }
}
