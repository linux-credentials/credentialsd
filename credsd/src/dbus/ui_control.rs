/// These methods are called by the credential service to control the UI.
#[proxy(
    gen_blocking = false,
    interface = "xyz.iinuwa.credentials.UiControl1",
    default_service = "xyz.iinuwa.credentials.UiControl",
    default_path = "/xyz/iinuwa/credentials/UiControl"
)]
// The #[proxy] macro renames this type to this creates a type UiControlServiceClientProxy
trait UiControlServiceClient {
    fn launch_ui(&self, request: ViewRequest) -> fdo::Result<()>;
}

#[derive(Debug)]
pub struct UiControlServiceClient {
    conn: Connection,
}
impl UiControlServiceClient {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    async fn proxy(&self) -> Result<UiControlServiceClientProxy, zbus::Error> {
        UiControlServiceClientProxy::new(&self.conn).await
    }
}
impl UiController for UiControlServiceClient {
    async fn launch_ui(&self, request: ViewRequest) -> Result<(), Box<dyn Error>> {
        self.proxy()
            .await?
            .launch_ui(request)
            .await
            .map_err(|err| err.into())
    }
}
