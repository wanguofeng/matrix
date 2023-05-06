/**
 * @copyright Copyright (c) 2021, Haier.Co, Ltd.
 * @file uh_shell.h
 * @author  maaiguo@haier.com
 * @brief
 * @date 2021-10-23
 *
 * @par History:
 * <table>
 * <tr><th>Date         <th>version <th>Author  <th>Description
 * <tr><td>2021-10-23   <td>1.0     <td>maaiguo <td>init version
 * <tr><td>2022-04-02   <td>1.1     <td>maaiguo <td>移植asr5822s的蓝牙功能，修改头文件
 * </table>
 */

#ifndef __UH_BLE_H__
#define __UH_BLE_H__

/**************************************************************************************************/
/*                         #include (依次为标准库头文件、非标准库头文件)                          */
/**************************************************************************************************/
#include "uh_types.h"


/**************************************************************************************************/
/*                                        其他条件编译选项                                        */
/**************************************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif


/**************************************************************************************************/
/*                                           常量定义                                             */
/**************************************************************************************************/


/**************************************************************************************************/
/*                                          全局宏定义                                            */
/**************************************************************************************************/


/**************************************************************************************************/
/*                                       全局数据类型定义                                         */
/**************************************************************************************************/
/**************************************************************************************************/
/* BLE通用功能数据类型定义                                                                        */
/**************************************************************************************************/
typedef uhos_u8 uhos_ble_addr_t[6];

/**
 * @enum BLE地址类型
 */
typedef enum
{
    UHOS_BLE_ADDRESS_TYPE_PUBLIC,                       //<! Public Device Address
    UHOS_BLE_ADDRESS_TYPE_RANDOM                        //<! Random Device Address
} uhos_ble_addr_type_t;

/**
 * @enum BLE的UUID类型
 */
typedef enum
{
    UHOS_BLE_UUID_TYPE_16,                              //<! 16位UUID
    UHOS_BLE_UUID_TYPE_128                              //<! 128位UUID
} uhos_ble_uuid_type_t;

/**
 * @enum BLE GAP规范定义的设备角色
 * @note GAP规范从数据的发起、接收者角度，提出了以下4个角色(Role)的概念
 */
typedef enum
{
    UHOS_BLE_GAP_BROADCASTER,                           //<! 广播者
    UHOS_BLE_GAP_OBSERVER,                              //<! 观察者
    UHOS_BLE_GAP_PERIPHERAL,                            //<! 外围设备
    UHOS_BLE_GAP_CENTRAL                                //<! 中央设备
} uhos_ble_gap_role_t;

/**
 * @enum BLE状态值定义
 */
typedef enum
{
    UHOS_BLE_SUCCESS = 0,                               //<! 成功
    UHOS_BLE_ERROR   = -1                               //<! 错误
} uhos_ble_status_t;

/**
 * @struct BLE的UUID描述结构
 */
typedef struct uhos_ble_uuid
{
    uhos_ble_uuid_type_t type;                          //<! UUID类型
    union
    {
        uhos_u16 uuid16;                                //<! 16位（2字节）UUID数值
        uhos_u8  uuid128[16];                           //<! 128位（16字节）UUID数值
    };
} uhos_ble_uuid_t;

/**************************************************************************************************/
/* BLE GAP层广播相关数据类型定义                                                                  */
/**************************************************************************************************/
/**
 * @enum 广播类型
 */
typedef enum
{
    UHOS_BLE_ADV_TYPE_CONNECTABLE_UNDIRECTED,           //<! 可连接的非定向广播
    UHOS_BLE_ADV_TYPE_SCANNABLE_UNDIRECTED,             //<! 可扫描的非定向广播
    UHOS_BLE_ADV_TYPE_NON_CONNECTABLE_UNDIRECTED,       //<! 不可连接的非定向广播
    UHOS_BLE_ADV_TYPE_CONNECTABLE_DIRECTED_HDC,         //<! 可连接的定向广播， high duty cycle
    UHOS_BLE_ADV_TYPE_CONNECTABLE_DIRECTED_LDC          //<! 可连接的定向广播，low duty cycle
} uhos_ble_gap_adv_type_t;

/**
 * @struct 广播参数描述结构
 */
typedef struct uhos_ble_gap_adv_param
{
    uhos_u16 adv_interval_min;                          //<! 最小广播间隔时间
    uhos_u16 adv_interval_max;                          //<! 最大广播间隔时间
                                                        //<! 广播间隔时间设置范围：0x0020~0x4000
                                                        //<! Time = N * 0.625msec，范围20ms~10.24sec
    uhos_ble_gap_adv_type_t adv_type;                   //<! 广播类型
    uhos_ble_addr_type_t    direct_addr_type;           //<! BLE地址类型

    struct
    {
        uhos_u8 ch_37_off : 1;                          //<! 37广播通道关闭标志位，1表示关闭
        uhos_u8 ch_38_off : 1;                          //<! 38广播通道关闭标志位，1表示关闭
        uhos_u8 ch_39_off : 1;                          //<! 39广播通道关闭标志为，1表示关闭
    } ch_mask;
} uhos_ble_gap_adv_param_t;

/**************************************************************************************************/
/* BLE GAP层扫描相关数据类型定义                                                                  */
/**************************************************************************************************/
/**
 * @enum 扫描类型
 */
typedef enum
{
    UHOS_BLE_SCAN_TYPE_PASSIVE,                         //<! 被动扫描
    UHOS_BLE_SCAN_TYPE_ACTIVE,                          //<! 主动扫描
} uhos_ble_gap_scan_type_t;

/**
 * @struct 扫描参数描述结构
 */
typedef struct uhos_ble_gap_scan_param
{
    uhos_u16 scan_interval;                             //<! 扫描间隔时间，取值范围: 0x0004~0x4000
                                                        //<! Time=N*0.625msec, 范围: 2.5msec~10.24sec
    uhos_u16 scan_window;                               //<! 扫描窗口，取值范围: 0x0004~0x4000
                                                        //<! Time=N*0.625msec, 范围: 2.5msec~10.24sec
    uhos_u16 timeout;                                   //<! 扫描超时时间，取值范围: 0x0001~0xFFFF sec
                                                        //<! 0x0000表示没有超时
} uhos_ble_gap_scan_param_t;

/**************************************************************************************************/
/* BLE GAP层连接相关数据类型定义                                                                  */
/**************************************************************************************************/
/**
 * @struct 连接参数描述结构
 */
typedef struct uhos_ble_gap_conn_param
{
    uhos_u16 min_conn_interval;                         //<! 最小连接间隔，取值范围: 0x0006~0x0C80
                                                        //<! Time=N*1.25msec, 范围: 7.5msec~4sec
    uhos_u16 max_conn_interval;                         //<! 最大连接间隔，取值范围: 0x0006~0x0C80
                                                        //<! Time=N*1.25msec, 范围: 7.5msec~4sec
    uhos_u16 slave_latency;                             //<! 从设备时延，取值范围: 0x0000~0x01F3
    uhos_u16 conn_sup_timeout;                          //<! 监控超时时间，取值范围: 0x000A~0x0C80
                                                        //<! Time=N*10msec, 范围: 100msec~32sec
} uhos_ble_gap_conn_param_t;

/**
 * @struct 连接描述结构
 */
typedef struct uhos_ble_gap_connect
{
    uhos_ble_addr_t           peer_addr;                //<! 地址
    uhos_ble_addr_type_t      type;                     //<! 地址类型
    uhos_ble_gap_role_t       role;                     //<! GAP层的角色类型（对端设备）
    uhos_ble_gap_conn_param_t conn_param;               //<! 连接参数
} uhos_ble_gap_connect_t;

/**************************************************************************************************/
/* BLE GAP层用户回调相关数据类型定义                                                              */
/**************************************************************************************************/
/**
 * @enum 断连原因
 */
typedef enum
{
    UNKNOW_OTHER_ERROR = 0,
    UHOS_BLE_CONNECTION_TIMEOUT = 1,                    //<! 连接超时
    UHOS_BLE_REMOTE_USER_TERMINATED,                    //<! 对端主动断开
    UHOS_BLE_LOCAL_HOST_TERMINATED                      //<! 本地主动断开
} uhos_ble_gap_disconnect_reason_t;

/**
 * @struct 断连描述结构
 */
typedef struct uhos_ble_gap_disconnect
{
    uhos_ble_gap_disconnect_reason_t reason;            //<! 断连原因
} uhos_ble_gap_disconnect_t;

/**
 * @struct 连接更新描述结构
 */
typedef struct uhos_ble_gap_connect_update
{
    uhos_ble_gap_conn_param_t conn_param;               //<! 连接参数
} uhos_ble_gap_connect_update_t;

/**
 * @enum 广播数据类型
 */
typedef enum
{
    ADV_DATA,      //<! 广播数据
    SCAN_RSP_DATA, //<! 扫描响应数据
    FULL_DATA,     // ADV_DATA, SCAN_RSP_DATA
} uhos_ble_gap_adv_data_type_t;

/**
 * @struct 上报的广播数据描述结构
 */
typedef struct uhos_ble_gap_adv_report
{
    uhos_ble_addr_t              peer_addr;             //<! 地址
    uhos_ble_addr_type_t         addr_type;             //<! 地址类型
    uhos_ble_gap_adv_data_type_t adv_type;              //<! 广播数据类型
    uhos_s8                      rssi;                  //<! 信号强度rssi数值
    uhos_u8                      data[31];              //<! 广播数据
    uhos_u8                      data_len;              //<! 广播数据长度
} uhos_ble_gap_adv_report_t;

/**
 * @enum GAP层用户回调事件定义
 */
typedef enum
{
    UHOS_BLE_GAP_EVT_CONNECTED = 0,                     //<! 连接事件
    UHOS_BLE_GAP_EVT_DISCONNET,                         //<! 断连事件
    UHOS_BLE_GAP_EVT_CONN_PARAM_UPDATED,                //<! 连接参数更新事件（未实现）
    UHOS_BLE_GAP_EVT_ADV_REPORT,                        //<! 广播数据上报事件（未实现）
} uhos_ble_gap_evt_t;

/**
 * @struct GAP层回调事件的参数结构定义
 */
typedef struct uhos_ble_gap_evt_param
{
    uhos_u16 conn_handle; //<! 连接句柄
    union
    {
        uhos_ble_gap_connect_t        connect;          //<! 连接数据
        uhos_ble_gap_disconnect_t     disconnect;       //<! 断连数据
        uhos_ble_gap_adv_report_t     report;           //<! 上报的广播数据
        uhos_ble_gap_connect_update_t update_conn;      //<! 连接更新数据
    };
} uhos_ble_gap_evt_param_t;

/**
 * @brief GAP层用户回调函数定义
 */
typedef void (*uhos_ble_gap_cb_t)(uhos_ble_gap_evt_t evt, uhos_ble_gap_evt_param_t *param);

/**************************************************************************************************/
/* BLE GATT层server相关数据类型定义                                                               */
/**************************************************************************************************/
/**
 * @enum GATT层Server端属性相关操作事件的类型定义
 */
typedef enum
{
    UHOS_BLE_GATTS_EVT_READ,                            //<! 读属性事件
    UHOS_BLE_GATTS_EVT_WRITE,                           //<! 写属性事件
    UHOS_BLE_GATTS_EVT_CCCD_UPDATE,                     //<! CCCD属性更新事件；CCCD是一种特殊的属性描述符
    UHOS_BLE_GATTS_EVT_READ_PERMIT_REQ,                 //<! 配对读属性请求事件
    UHOS_BLE_GATTS_EVT_WRITE_PERMIT_REQ                 //<! 配对写属性请求事件
} uhos_ble_gatts_evt_t;

/**
 * @struct 写数据的描述结构；该结构描述了写数据相关事件回调函数的参数结构，写数据事件有：
 *         UHOS_BLE_GATTS_EVT_WRITE
 *         UHOS_BLE_GATTS_EVT_CCCD_UPDATE
 *         UHOS_BLE_GATTS_EVT_WRITE_PERMIT_REQ
 */
typedef struct uhos_ble_gatts_write
{
    uhos_u16 value_handle;                              //<! 特性值句柄
    uhos_u8  offset;                                    //<! 偏移
    uhos_u8 *data;                                      //<! 指向数据的指针
    uhos_u16 len;                                       //<! 数据的字节数
} uhos_ble_gatts_write_t;

/**
 * @struct 读数据的描述结构；该结构描述了读数据相关事件回调函数的参数结构，读数据事件有：
 *         UHOS_BLE_GATTS_EVT_READ
 *         UHOS_BLE_GATTS_EVT_READ_PERMIT_REQ
 */
typedef struct uhos_ble_gatts_read
{
    uhos_u16  value_handle;                             //<! 特性值句柄
    uhos_u8   offset;                                   //<! 偏移
    uhos_u8 **data;                                     //<! 指向数据缓存区指针的指针
    uhos_u16 *len;                                      //<! 指向读取数据字节数的指针
} uhos_ble_gatts_read_t;

/**
 * @struct GATT层server端服务属性事件回调参数描述结构
 */
typedef struct uhos_ble_gatts_evt_param
{
    uhos_u16 conn_handle;                               //<! 连接句柄
    uhos_u32 cccd;                                      //<! cccd值
    union
    {
        uhos_ble_gatts_write_t write;                   //<! 写数据
        uhos_ble_gatts_read_t  read;                    //<! 读数据
    };
} uhos_ble_gatts_evt_param_t;

/**
 * @brief GATT层Server端的事件回调函数定义
 */
typedef uhos_ble_status_t (*uhos_ble_gatts_cb_t)(
    uhos_ble_gatts_evt_t        evt,
    uhos_ble_gatts_evt_param_t *param);

/**
 * @enum 服务类型
 */
typedef enum
{
    UHOS_BLE_PRIMARY_SERVICE = 1,                       //<! 首要服务
    UHOS_BLE_SECONDARY_SERVICE                          //<! 次要服务
} uhos_ble_gatts_service_t;

/**
 * @struct 特征值的扩展描述符结构
 */
typedef struct uhos_ble_gatts_char_desc_ext_prop
{
    uhos_u8 reliable_write;                             //<! Reliable Write写属性
    uhos_u8 writeable;                                  //<! Writeable Auxiliaries写属性
} uhos_ble_gatts_char_desc_ext_prop_t;

/**
 * @struct 特征值的用户描述符结构
 */
typedef struct uhos_ble_gatts_char_desc_user_desc
{
    uhos_char *string;                                    //<! 特征值的文字描述信息
    uhos_u8  len;                                       //<! 文字描述信息长度
} uhos_ble_gatts_char_desc_user_desc_t;

/**
 * @struct 特征值格式描述符
 */
typedef struct uhos_ble_gatts_char_desc_cpf
{
    uhos_u8  format;                                    //<! 数据类型
    uhos_u8  exponent;                                  //<! 数据的指数
    uhos_u16 unit;                                      //<! 单位
    uhos_u8  name_space;                                //<! 名字空间
    uhos_u16 desc;                                      //<! 描述信息
} uhos_ble_gatts_char_desc_cpf_t;

/**
 * @struct GATT层Server端特征描述符数据库结构
 * @note if char property contains notify , then SHOULD include cccd(client characteristic
 *       configuration descriptor automatically). The same to sccd when BROADCAST enabled
 */
typedef struct uhos_ble_gatts_char_desc_db
{
    uhos_ble_gatts_char_desc_ext_prop_t * extend_prop;  //<! 扩展描述符
    uhos_ble_gatts_char_desc_cpf_t *      char_format;  //<! 格式描述符
    uhos_ble_gatts_char_desc_user_desc_t *user_desc;    //<! 用户描述符
} uhos_ble_gatts_char_desc_db_t;

/**
 * @enum GATT层Server端的特征的特性定义，按位使用，可以组合
 * @note default:  no authentication ; no encrption; configurable authorization
 */
typedef enum
{
    UHOS_BLE_CHAR_PROP_BROADCAST           = 0x01,      //<! 特征值应用于广播
    UHOS_BLE_CHAR_PROP_READ                = 0x02,      //<! 可读
    UHOS_BLE_CHAR_PROP_WRITE_WITHOUT_RESP  = 0x04,      //<! 可写（无需响应）
    UHOS_BLE_CHAR_PROP_WRITE               = 0x08,      //<! 可写（需要响应）
    UHOS_BLE_CHAR_PROP_NOTIFY              = 0x10,      //<! 可发送通知
    UHOS_BLE_CHAR_PROP_INDICATE            = 0x20,      //<! 可发送指示
    UHOS_BLE_CHAR_PROP_AUTH_SIGNED_WRITE   = 0x40,      //<! 需要认证的写
    UHOS_BLE_CHAR_PROP_EXTENDED_PROPERTIES = 0x80       //<! 携带扩展描述符
} uhos_ble_gatts_char_property_t;

/**
 * @struct GATT层Server端的特征描述结构
 */
typedef struct uhos_ble_gatts_char_db
{
    uhos_ble_uuid_t               char_uuid;            //<! 特征UUID
    uhos_u8                       char_property;        //<! 特征属性 @ref uhos_ble_gatts_char_property_t
    uhos_u8 *                     p_value;              //<! 特征值的初始值
    uhos_u16                      char_value_len;       //<! 特征值的长度
    uhos_u16                      char_value_handle;    //<! 特征值句柄
    uhos_u8                       is_variable_len;      //<! 特征值长度是否变长
    uhos_u8                       rd_author;            //<! 特征值读授权. Enable or Disable
    uhos_u8                       wr_author;            //<! 特征值写授权. Enable or Disable
    uhos_u8                       is_notification_enabled;
    uhos_ble_gatts_char_desc_db_t char_desc_db;         //<! 特征描述符数据库
} uhos_ble_gatts_char_db_t;

/**
 * @struct GATT层Server端的服务描述结构
 */
typedef struct uhos_ble_gatts_srv_db
{
    uhos_ble_gatts_service_t  srv_type;                 //<! 服务类型：首要服务或次要服务
    uhos_u16                  srv_handle;               //<! 服务句柄
    uhos_ble_uuid_t           srv_uuid;                 //<! 服务UUID
    uhos_u8                   char_num;                 //<! 特征数量
    uhos_ble_gatts_char_db_t *p_char_db;                //<! 指向特征数据库的指针
} uhos_ble_gatts_srv_db_t;

/**
 * @struct GATT层Server端的服务架构数据库定义
 */
typedef struct uhos_ble_gatts_db
{
    uhos_ble_gatts_srv_db_t *p_srv_db;                  //<! 服务数据库
    uhos_u8                  srv_num;                   //<! 服务数量
} uhos_ble_gatts_db_t;

/**************************************************************************************************/
/* BLE GATT层client相关数据类型定义                                                               */
/**************************************************************************************************/
/**
 * @struct GATT层服务句柄范围定义
 */
typedef struct uhos_ble_handle_range
{
    uhos_u16 begin_handle;                              //<! 起始服务地址
    uhos_u16 end_handle;                                //<! 结束服务地址
} uhos_ble_handle_range_t;

/**
 * @enum GATT层Client端的事件定义
 */
typedef enum
{
    //<! this event generated in responses to a discover primary service procedure
    UHOS_BLE_GATTC_EVT_PRIMARY_SERVICE_DISCOVER_RESP = 0,
    //<! this event generated when a discover primary service procedure is finished
    UHOS_BLE_GATTC_EVT_PRIMARY_SERVICE_DISCOVER_DONE,
    //<! this event generated in responses to a discover characteristic procedure
    UHOS_BLE_GATTC_EVT_CHAR_DISCOVER_RESP,
    //<! this event generated when a discover characteristic procedure is finished
    UHOS_BLE_GATTC_EVT_CHAR_DISCOVER_DONE,
    //<! this event generated in responses to a discover charicteristic by uuid procedure
    UHOS_BLE_GATTC_EVT_CHAR_DISCOVER_BY_UUID_RESP,
    //<! this event generated in responses to a discover characteristic descriptor procedure
    UHOS_BLE_GATTC_EVT_CHAR_DESC_DISCOVER_RESP,
    //<! this event generated when a discover characteristic descriptor procedure is finished
    UHOS_BLE_GATTC_EVT_CHAR_DESC_DISCOVER_DONE,
    //<! this event generated in responses to a discover char clt cfg descriptor procedure
    UHOS_BLE_GATTC_EVT_CCCD_DISCOVER_RESP,
    //<! this event generated in responses to a read_characteristic_value procedure
    UHOS_BLE_GATTC_EVT_READ_CHAR_VALUE_RESP,
    //<! this event generated in responses to a read_charicteristic value by uuid procedure
    UHOS_BLE_GATTC_EVT_READ_CHAR_VALUE_BY_UUID_RESP,
    //<! this event generated in responses to a read using_uuid procedure
    UHOS_BLE_GATTC_EVT_READ_USING_UUID_RESP,
    //<! this event generated when a read_using_uuid procedure is finished
    UHOS_BLE_GATTC_EVT_READ_USING_UUID_DONE,
    //<! this event generated in responses to a write_characteristic_value_with_response procedure
    UHOS_BLE_GATTC_EVT_WRITE_RESP,
    //<! this event is generated when peer gatts device send a notification
    UHOS_BLE_GATTC_EVT_NOTIFICATION,
    //<! this event is generated when peer gatts device send a indication
    UHOS_BLE_GATTC_EVT_INDICATION,
    //<! this event generated when a exchange_mtu procedure is finished
    UHOS_BLE_GATTC_EVT_EXCHANGE_MTU_DONE,
} uhos_ble_gattc_evt_t;

/**
 * @struct UHOS_BLE_GATTC_EVT_PRIMARY_SERVICE_DISCOVER_RESP event callback parameters
 */
typedef struct uhos_ble_gattc_prim_srv_disc_rsp
{
    uhos_ble_handle_range_t primary_srv_range;
    uhos_ble_uuid_t         srv_uuid;
} uhos_ble_gattc_prim_srv_disc_rsp_t;

/**
 * @struct UHOS_BLE_GATTC_EVT_CHAR_DISCOVER_RESP event callback parameters
 */
typedef struct uhos_ble_gattc_char_disc_rsp
{
    uhos_ble_handle_range_t char_range;
    uhos_u8                 char_properties;
    uhos_u16                char_value_handle;
    uhos_ble_uuid_t         char_uuid;
} uhos_ble_gattc_char_disc_rsp_t;

/*
 * @struct UHOS_BLE_GATTC_EVT_CCCD_DISCOVER_RESP event callback parameters
 * */
typedef struct uhos_ble_gattc_clt_cfg_desc_disc_rsp
{
    uhos_u16 desc_handle;
    uhos_u8  succ;                                      //<! true: exit cccd and return correctly
} uhos_ble_gattc_clt_cfg_desc_disc_rsp_t;

/**
 * @struct UHOS_BLE_GATTC_EVT_CHAR_DESC_DISCOVER_RESP event callback parameters
 */
typedef struct uhos_ble_gattc_char_desc_disc_rsp
{
    uhos_u16        desc_handle;
    uhos_ble_uuid_t char_desc_uuid;
} uhos_ble_gattc_char_desc_disc_rsp_t;

/*
 * @struct UHOS_BLE_GATTC_EVT_WRITE_RESP event callback parameters
 *  */
typedef struct uhos_ble_gattc_write_rsp
{
    uhos_u8 succ;
} uhos_ble_gattc_write_rsp_t;

/**
 * @struct UHOS_BLE_GATTC_EVT_READ_CHAR_VALUE_RESP event callback paramters
 */
typedef struct uhos_ble_gattc_read_char_value_rsp
{
    uhos_u16 len;
    uhos_u8 *data;
    uhos_s32 succ;                                      //<! >0 : return correctly; <=0 error
} uhos_ble_gattc_read_char_value_rsp_t;

/**
 * @struct UHOS_BLE_GATTC_EVT_READ_USING_UUID_RESP event callback paramters
 */
typedef struct uhos_ble_gattc_read_using_uuid_rsp
{
    uhos_u16 char_value_handle;
    uhos_u8  len;
    uhos_u8 *data;
} uhos_ble_gattc_read_using_uuid_rsp_t;

/*
 * @struct UHOS_BLE_GATTC_EVT_READ_CHAR_VALUE_BY_UUID_RESP event callback paramters
 * */
typedef struct uhos_ble_gattc_read_char_value_by_uuid_rsp
{
    uhos_u16 char_value_handle;
    uhos_u8  len;
    uhos_u8 *data;
    uhos_u8  succ;                      //<! true: exist the specified characteristic and return correctly
} uhos_ble_gattc_read_char_value_by_uuid_rsp_t;

/**
 * @struct UHOS_BLE_GATTC_EVT_PRIMARY_SERVICE_DISCOVER_DONE
 *         UHOS_BLE_GATTC_EVT_CHAR_DISCOVER_DONE
 *         UHOS_BLE_GATTC_EVT_CHAR_DESC_DISCOVER_DONE
 *         UHOS_BLE_GATTC_EVT_READ_USING_UUID_DONE
 *         UHOS_BLE_GATTC_EVT_WRITE_RESP
 *         UHOS_BLE_GATTC_EVT_EXCHANGE_MTU_DONE
 *         event callback parameters
 */
typedef struct uhos_ble_gattc_common_rsp
{
    uhos_s32 succ;                                      //<! >0 : return correctly; <=0 error
} uhos_ble_gattc_common_rsp_t;

/**
 * @struct  UHOS_BLE_GATTC_EVT_NOTIFICATION
 *          UHOS_BLE_GATTC_EVT_INDICATION
 *          event callback parameters
 */
typedef struct uhos_ble_gattc_notification_or_indication
{
    uhos_u16 handle;
    uhos_u8  len;
    uhos_u8 *pdata;
} uhos_ble_gattc_notification_or_indication_t;

/**
 * @struct UHOS_BLE_GATTC_EVT_MTU event callback parameters
 */
typedef struct uhos_ble_gattc_mtu_rsp
{
    uhos_u16 mtu;
} uhos_ble_gattc_mtu_rsp_t;

/**
 * @struct GATT层Client端事件回调参数
 * @note GATTC callback parameters union
 */
typedef struct uhos_ble_gattc_evt_param
{
    uhos_u16 conn_handle;
    union
    {
        uhos_ble_gattc_prim_srv_disc_rsp_t           srv_disc_rsp;
        uhos_ble_gattc_char_disc_rsp_t               char_disc_rsp;
        uhos_ble_gattc_clt_cfg_desc_disc_rsp_t       clt_cfg_desc_disc_rsp;
        uhos_ble_gattc_char_desc_disc_rsp_t          char_desc_disc_rsp;
        uhos_ble_gattc_write_rsp_t                   write_rsp;
        uhos_ble_gattc_read_char_value_rsp_t         read_char_value_rsp;
        uhos_ble_gattc_read_using_uuid_rsp_t         read_using_uuid_rsp;
        uhos_ble_gattc_read_char_value_by_uuid_rsp_t read_char_value_by_uuid_rsp;
        uhos_ble_gattc_common_rsp_t                  common_rsp;
        uhos_ble_gattc_notification_or_indication_t  notification;
        uhos_ble_gattc_mtu_rsp_t                     mtu_rsp;
    };
} uhos_ble_gattc_evt_param_t;

/**
 * @brief  GATT client的回调函数
 */
typedef void (*uhos_ble_gattc_callback_t)(
    uhos_ble_gattc_evt_t evt,
    uhos_ble_gattc_evt_param_t *param);


/**************************************************************************************************/
/*                                          全局变量声明                                          */
/**************************************************************************************************/


/**************************************************************************************************/
/*                                          全局函数原型                                          */
/**************************************************************************************************/
/**************************************************************************************************/
/* BLE通用功能接口原型                                                                            */
/**************************************************************************************************/
extern uhos_ble_status_t uhos_ble_address_get(uhos_ble_addr_t mac);
extern uhos_ble_status_t uhos_ble_enable(void);
extern uhos_ble_status_t uhos_ble_disable(void);
extern uhos_ble_status_t uhos_ble_rssi_start(uhos_u16 conn_handle);
extern uhos_ble_status_t uhos_ble_rssi_get_detect(uhos_u16 conn_handle, uhos_s8 *rssi);
extern uhos_ble_status_t uhos_ble_rssi_get(uhos_u16 conn_handle, uhos_s8 *rssi);
extern uhos_ble_status_t uhos_ble_rssi_stop(uhos_u16 conn_handle);
extern uhos_ble_status_t uhos_ble_tx_power_set(uhos_u16 conn_handle, uhos_s8 tx_power);

/**************************************************************************************************/
/* BLE GAP层广播相关功能接口原型                                                                  */
/**************************************************************************************************/
extern uhos_ble_status_t uhos_ble_gap_adv_data_set(
    uhos_u8 const *p_data, 
    uhos_u8 dlen,
    uhos_u8 const *p_sr_data,
    uhos_u8 srdlen);
extern uhos_ble_status_t uhos_ble_gap_adv_start(uhos_ble_gap_adv_param_t *p_adv_param);
extern uhos_ble_status_t uhos_ble_gap_reset_adv_start(void);
extern uhos_ble_status_t uhos_ble_gap_adv_stop(void);

/**************************************************************************************************/
/* BLE GAP层扫描相关功能接口原型                                                                  */
/**************************************************************************************************/
extern uhos_ble_status_t uhos_ble_gap_scan_start(
    uhos_ble_gap_scan_type_t scan_type,
    uhos_ble_gap_scan_param_t scan_param);
extern uhos_ble_status_t uhos_ble_gap_scan_stop(void);

/**************************************************************************************************/
/* BLE GAP层连接相关功能接口原型                                                                  */
/**************************************************************************************************/
extern uhos_ble_status_t uhos_ble_gap_update_conn_params(
    uhos_u16 conn_handle,
    uhos_ble_gap_conn_param_t conn_params);
extern uhos_ble_status_t uhos_ble_gap_disconnect(uhos_u16 conn_handle);
extern uhos_ble_status_t uhos_ble_gap_connect(uhos_ble_gap_scan_param_t scan_param,
                                              uhos_ble_gap_connect_t conn_param);
/**************************************************************************************************/
/* BLE GAP层用户回调相关功能接口原型                                                              */
/**************************************************************************************************/
extern uhos_ble_status_t uhos_ble_gap_callback_register(uhos_ble_gap_cb_t cb);

/**************************************************************************************************/
/* BLE GATT层server相关功能接口原型                                                               */
/**************************************************************************************************/
extern uhos_ble_status_t uhos_ble_gatts_callback_register(uhos_ble_gatts_cb_t cb);
extern uhos_ble_status_t uhos_ble_gatts_service_set(uhos_ble_gatts_db_t *uhos_ble_service_database);
extern uhos_ble_status_t uhos_ble_gatts_notify_or_indicate(
    uhos_u16 conn_handle,
    uhos_u16 srv_handle,
    uhos_u16 char_value_handle,
    uhos_u8 offset,
    uhos_u8 *p_value,
    uhos_u16 len);
extern uhos_ble_status_t uhos_ble_gatts_mtu_default_set(uhos_u16 mtu);
extern uhos_ble_status_t uhos_ble_gatts_mtu_get(uhos_u16 conn_handle, uhos_u16 *mtu_size);

/**************************************************************************************************/
/* BLE GATT层client相关功能接口原型                                                               */
/**************************************************************************************************/
extern uhos_ble_status_t uhos_ble_gattc_callback_register(uhos_ble_gattc_callback_t cb);
extern uhos_ble_status_t uhos_ble_gattc_primary_service_discover_by_uuid(
    uhos_u16 conn_handle,
    uhos_ble_handle_range_t *handle_range,
    uhos_ble_uuid_t *p_srv_uuid);
extern uhos_ble_status_t uhos_ble_gattc_char_discover_by_uuid(
    uhos_u16 conn_handle,
    uhos_ble_handle_range_t *handle_range,
    uhos_ble_uuid_t *p_char_uuid);
extern uhos_ble_status_t uhos_ble_gattc_clt_cfg_descriptor_discover(
    uhos_u16 conn_handle,
    uhos_ble_handle_range_t *handle_range);
extern uhos_ble_status_t uhos_ble_gattc_read_char_value_by_uuid(
    uhos_u16 conn_handle,
    uhos_ble_handle_range_t *handle_range,
    uhos_ble_uuid_t *p_char_uuid);
extern uhos_ble_status_t uhos_ble_gattc_write_with_rsp(
    uhos_u16 conn_handle,
    uhos_u16 handle,
    uhos_u8 *p_value,
    uhos_u8 len);
extern uhos_ble_status_t uhos_ble_gattc_write_cmd(
    uhos_u16 conn_handle,
    uhos_u16 handle,
    uhos_u8 *p_value,
    uhos_u8 len);


#ifdef __cplusplus
}
#endif

#endif /* __UH_BLE_H__ */

